# Splunk metrics sink (designed)

`cloudflow-sink-splunk-metrics` is a designed, not-yet-implemented second
Splunk sink. It reads the same wire streams as the event sink
(`docs/splunk-output.md`) but delivers to Splunk's **metrics** index instead of
its event index — numeric measurements with dimensions, which are far cheaper
to store and much faster to chart and alert on than searching full event JSON
at wire volume.

The two Splunk sinks are complementary, not alternatives:

| Sink | Splunk endpoint | Purpose |
|---|---|---|
| `cloudflow-sink-splunk` (implemented) | HEC `/services/collector/event` | full-fidelity forensic record; every field searchable |
| `cloudflow-sink-splunk-metrics` (designed) | HEC `/services/collector` (metric) | rates, latency distributions, counts for dashboards & alerting |

## Why this is a small addition

A metrics sink is **another consumer group on the same streams**
(`sink-splunk-metrics` alongside `sink-splunk`), so it reuses the entire sink
spine unchanged: the hiredis consumer loop, `XAUTOCLAIM` recovery,
ack-after-delivery, the libcurl HEC client with backoff/retry, the
dead-letter path, and the stats line. Consumer groups isolate progress, so the
metrics sink never blocks the event sink or vice versa (see
`docs/redis-streams.md`).

Only the **transform** differs: instead of one HEC event object per
`CloudFlowEvent`, the metrics transform emits one or more Splunk metric points.
Everything else — config schema, token handling (env-only, D6), retry, poison
bisection, dead-letter — is identical and shared by design.

## Metric-point format

Splunk metrics over HEC use the same POST endpoint with a metric-shaped
payload:

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
    "cf_rcode": "NOERROR",
    "cf_qtype": "A",
    "cf_client_ip": "192.0.2.10",
    "source_host": "dns01"
  }
}
```

`metric_name:<name>` carries the value; the other `fields` are dimensions.
`time` is the observed wire time, exactly as the event sink (identity of the
measurement is the observed moment, not ingest). Multiple measurements from one
event are emitted as multiple metric points sharing the same dimensions.

## Metric mapping (the contract)

Like the HEC event mapping, this mapping is a stable contract with committed
golden files. Initial metrics:

### DNS (the primary motivation — `docs/dns-source.md`)

- `dns.rtt_seconds` — the transaction RTT (from `rtt_nanos`), dimensioned by
  `cf_role` (client-facing / backend / recursion-upstream), `cf_rcode`,
  `cf_qtype`, and `cf_server_ip`. This is a distribution metric: Splunk
  computes percentiles server-side.
- `dns.transactions_total` — count = 1 per `dns.transaction.observed`,
  dimensioned by `cf_role` / `cf_rcode` / `cf_qtype`, so query rate and
  error-rate breakdowns are aggregations, not event searches.
- `dns.unanswered_total` / `dns.unmatched_total` — count = 1 per
  `dns.query.unanswered` / `dns.response.unmatched`, dimensioned by `cf_role`;
  the unanswered rate is a loss/health signal and the unmatched rate is a
  capture-gap / spoofing signal.

Dimensions use the normalized identity from `docs/event-model.md` (client IP,
role) rather than raw nested `src_ip`.

### DHCP

- `dhcp.events_total` — count = 1 per DHCP event, dimensioned by `source_type`
  (dhcpv4 / dhcpv6), `cf_message_type` (DISCOVER / OFFER / … ), and
  `cf_is_relayed`. Lease-churn and message-mix dashboards come from
  aggregating this rather than searching events.
- Because a DHCP client's L3 source is usually `0.0.0.0`, DHCP metric
  dimensions use the client key (MAC / client-id) per `docs/event-model.md`,
  not `src_ip`. High-cardinality dimensions (per-MAC) are opt-in via config —
  cardinality is a metrics-store cost, so the default keeps dimensions coarse.

## Configuration

Extends the `splunk-sink.yaml` schema with a metrics variant:
`splunk.metrics_index`, an `enabled_metrics` allowlist, and per-metric
cardinality controls (which dimensions to include). The HEC endpoint and token
follow the same env-only rule as the event sink (D6).

## Delivery guarantees

Identical to the event sink: metric points are acknowledged only after a 2xx;
transient failures back off and retry (Redis is the buffer); a malformed event
is dead-lettered (`cloudflow:v1:deadletter:sink-splunk-metrics`) rather than
blocking the group. Metrics are lossy by *nature* (a dropped metric point is a
missing sample, not a lost record) — but CloudFlow still counts every drop, so
even metric loss is visible.

## Roadmap

Implement after the DNS source lands: DNS RTT and rate metrics are the data
that most justifies a dedicated metrics store, and building the metrics
mapping against DHCP-only traffic would exercise only a fraction of it. The
work is small because it reuses the sink spine; the design effort is choosing
the metric set and dimensions above, which this document fixes as the contract.
