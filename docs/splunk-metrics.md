# Splunk metrics sink (implemented)

`cloudflow-sink-splunk-metrics` is the second Splunk sink. It reads the same
wire streams as the event sink (`docs/splunk-output.md`) but delivers to
Splunk's **metrics** index instead of its event index — numeric measurements
with dimensions, which are far cheaper to store and much faster to chart and
alert on than searching full event JSON at wire volume.

The two Splunk sinks are complementary, not alternatives:

| Sink | Splunk endpoint | Purpose |
|---|---|---|
| `cloudflow-sink-splunk` (implemented) | HEC `/services/collector/event` | full-fidelity forensic record; every field searchable |
| `cloudflow-sink-splunk-metrics` (implemented) | HEC `/services/collector` (metric) | rates, latency distributions, counts for dashboards & alerting |

## Why this is a small addition

A metrics sink is **another consumer group on the same streams**
(`sink-splunk-metrics` alongside `sink-splunk`), so it reuses the entire sink
spine unchanged (`libs/cloudflow-sink-core`): the hiredis consumer loop,
`XAUTOCLAIM` recovery, ack-after-delivery, the libcurl HEC client with
backoff/retry, the dead-letter path, and the stats line. Consumer groups
isolate progress, so the metrics sink never blocks the event sink or vice versa
(see `docs/redis-streams.md`).

Only the **transform** differs: instead of one HEC event object per
`CloudFlowEvent`, the metrics transform (`src/metrics_transform.c`) emits one or
more Splunk metric points. Everything else — config schema, token handling
(env-only, D6), retry, poison bisection, dead-letter — is identical and shared
by design.

## Metric-point format

Splunk metrics over HEC use the same POST endpoint with a metric-shaped
payload; the sink emits one such object per measurement, newline-delimited:

```json
{
  "time": 1730000000.123456789,
  "source": "cloudflow:v1:wire:dns",
  "sourcetype": "cloudflow:metric",
  "host": "<source_host>",
  "index": "<config splunk.metrics_index>",
  "fields": {
    "metric_name:dns.rtt_seconds": 0.004213,
    "cf_role": "client_facing",
    "cf_service_role": "authoritative",
    "cf_rcode": "NOERROR",
    "cf_qtype": "A",
    "cf_server_ip": "192.0.2.53"
  }
}
```

`metric_name:<name>` carries the value; the other `fields` are dimensions.
`time` is the observed wire time (`observed_time_unix_nano / 1e9`, rendered with
exactly 9 decimals), exactly as the event sink (identity of the measurement is
the observed moment, not ingest). Multiple measurements from one event are
emitted as multiple metric points sharing the same dimensions. `sourcetype` is
always `cloudflow:metric`; `index` is `splunk.metrics_index` (omitted when
empty); object keys are emitted in sorted order for stable diffs (the golden
suite compares structurally).

## Metric mapping (the contract)

Like the HEC event mapping, this mapping is a stable contract with committed
golden files (`sinks/cloudflow-sink-splunk-metrics/tests/golden/`).

### DNS (the primary motivation — `docs/dns-source.md`)

- `dns.rtt_seconds` — the transaction RTT (`rtt_nanos / 1e9`), emitted only when
  `rtt_valid`. This is a distribution metric: Splunk computes percentiles
  server-side.
- `dns.transactions_total` — count = 1 per `dns.transaction.observed`, so query
  rate and error-rate breakdowns are aggregations, not event searches.

  Both `dns.transaction.observed` metrics are dimensioned by `cf_role` (the leg:
  client-facing / backend / recursion-upstream), `cf_service_role` (the
  operator tier from `DnsTransactionEvent.service_role`, omitted when empty),
  `cf_rcode`, `cf_qtype`, and `cf_server_ip`. `cf_service_role` is the per-tier
  (dnsdist / recursor / authoritative) breakdown alongside the wire-decided
  `cf_role`; it is a first-class dimension of this contract.
- `dns.unanswered_total` / `dns.unmatched_total` — count = 1 per
  `dns.query.unanswered` / `dns.response.unmatched`, dimensioned by `cf_role`
  and `cf_service_role`; the unanswered rate is a loss/health signal and the
  unmatched rate is a capture-gap / spoofing signal.

Dimensions use the normalized identity from `docs/event-model.md` (client IP,
role) rather than raw nested `src_ip`.

### DHCP

- `dhcp.events_total` — count = 1 per DHCP event, dimensioned by `source_type`
  (dhcpv4 / dhcpv6), `cf_message_type` (DISCOVER / OFFER / SOLICIT / … ), and
  `cf_is_relayed`. Lease-churn and message-mix dashboards come from aggregating
  this rather than searching events.
- Because a DHCP client's L3 source is usually `0.0.0.0`, DHCP metric dimensions
  use the client key (MAC / client-id / DUID) per `docs/event-model.md`, not
  `src_ip`, exposed as the `cf_client_key` dimension. High-cardinality
  dimensions (per-MAC) are opt-in via config — cardinality is a metrics-store
  cost, so the default keeps dimensions coarse and leaves `cf_client_key` off.

An event that maps to no enabled metric (e.g. a disabled metric) is a
successful no-op with no output; only a genuinely unmappable event (missing
envelope / unset payload) is dead-lettered.

## Configuration

Extends the `splunk-sink.yaml` schema with a metrics variant
(`configs/examples/splunk-metrics.yaml`): `splunk.metrics_index`, an
`enabled_metrics` allowlist (empty ⇒ all metrics), and per-metric cardinality
controls under `splunk.dimensions` selecting which dimensions to include
(`dns_server_ip`, `dns_qtype` default on; `dhcp_client_key` default off). The
HEC endpoint is `/services/collector` (metric, via `splunk.hec_path`) and the
token follows the same env-only rule as the event sink (D6).

## Delivery guarantees

Identical to the event sink: metric points are acknowledged only after a 2xx;
transient failures back off and retry (Redis is the buffer); a malformed event
is dead-lettered (`cloudflow:v1:deadletter:sink-splunk-metrics`) rather than
blocking the group. Metrics are lossy by *nature* (a dropped metric point is a
missing sample, not a lost record) — but CloudFlow still counts every drop, so
even metric loss is visible.
