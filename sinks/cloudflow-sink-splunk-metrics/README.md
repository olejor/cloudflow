# cloudflow-sink-splunk-metrics

Redis Streams to Splunk HEC **metrics** sink for CloudFlow. C11 (decision D1,
`docs/architecture.md`). It reads the same wire streams as the event sink but
delivers numeric measurements with dimensions to Splunk's metrics index (HEC
`/services/collector`) instead of full event JSON to the event index — cheaper
to store and far faster to chart and alert on at wire volume. The
**CloudFlowEvent → Splunk metric-point mapping** and the consumer/retry/
dead-letter behavior are the contract documented in `docs/splunk-metrics.md`;
the golden files in `tests/golden/` are what the C transform is proven against.

It is complementary to `cloudflow-sink-splunk` (the event sink), not an
alternative: a second consumer group (`sink-splunk-metrics`) on the same
streams, so it reuses the entire sink spine unchanged — only the transform
differs.

Pipeline:

```text
XAUTOCLAIM (min-idle 60s) -> XREADGROUP (group sink-splunk-metrics)
    -> protobuf-c decode -> metric points (yyjson) -> HEC POST (libcurl, batched)
        -> XACK on 2xx only
         \-> dead-letter stream on poison events (decode / HTTP 4xx)
```

## Layout

The generic sink spine — the consumer group, HEC client, dead-letter writer,
base config/stats, and the run loop — lives in `libs/cloudflow-sink-core`
(synergy item A1) and is shared with the event sink. This app keeps only the
metrics-specific pieces:

```text
src/
  main.c                thin CLI: parse config, supply the metrics transform,
                        call cf_sink_run; --stdout, --once, --version
  config.{c,h}          metrics config: metrics_index, enabled_metrics allowlist,
                        dimensions cardinality controls, layered on cf_sink_config
  metrics_transform.{c,h} protobuf-c CloudFlowEvent -> yyjson metric points
tests/                  golden metric-point suite + goldens + Python golden
                        generator (reuses the event sink's committed bindings)
config/                 example config
systemd/                unit file
Makefile                build/cloudflow-sink-splunk-metrics; `all test test-asan clean`
```

## Building

Depends on: `libcloudflow-sink-core.a`, `libcloudflow-core.a`,
`libcloudflow-codec.a`, the vendored `third_party/yyjson`, and the system
libraries hiredis, libcurl, libyaml, libprotobuf-c (all via `pkg-config`).

```sh
make -C sinks/cloudflow-sink-splunk-metrics all       # -> build/cloudflow-sink-splunk-metrics
make -C sinks/cloudflow-sink-splunk-metrics test      # CUnit golden suite
make -C sinks/cloudflow-sink-splunk-metrics test-asan # same suite under ASan/UBSan
make -C sinks/cloudflow-sink-splunk-metrics clean
```

## Running

```sh
# Replay / milestone check: print metric-point JSON to stdout instead of POSTing.
build/cloudflow-sink-splunk-metrics -c config/splunk-metrics.example.yaml --stdout --once

# Real delivery to Splunk HEC (token from the environment, see below):
export SPLUNK_HEC_TOKEN=...
build/cloudflow-sink-splunk-metrics -c /etc/cloudflow/splunk-metrics.yaml
```

Flags: `-c/--config PATH` (required), `--stdout` (print metric-point JSON lines
instead of POSTing), `--once` (drain what is pending, then exit), `--version`.
`SIGTERM`/`SIGINT` flush the in-flight batch once, ack what succeeded, then exit
(at-least-once; unacked entries stay pending).

The HEC token is **never** read from YAML. Set the environment variable named
by `splunk.hec_token_env` (default `SPLUNK_HEC_TOKEN`). A token-looking string
where an env-var *name* is expected, or a literal `splunk.hec_token` key in
YAML, is a fatal startup error (decision D6). The token is never logged.

## Configuration

Schema (see `config/splunk-metrics.example.yaml`, identical to
`configs/examples/splunk-metrics.yaml`). The base keys (`service`, `redis`,
`splunk.hec_url`/`hec_path`/`hec_token_env`/batch/flush/timeout/tls) are the
shared sink config; the metrics-specific additions are:

```yaml
splunk:
  hec_url: https://splunk.example.com:8088
  hec_path: /services/collector       # the metric HEC endpoint (not /event)
  metrics_index: cloudflow_metrics    # Splunk metrics index the points carry
  enabled_metrics:                    # allowlist; omit / empty => all metrics
    - dns.rtt_seconds
    - dns.transactions_total
    - dns.unanswered_total
    - dns.unmatched_total
    - dhcp.events_total
  dimensions:                         # cardinality controls (which dims to emit)
    dns_server_ip: true               # cf_server_ip on DNS metrics (default: true)
    dns_qtype: true                   # cf_qtype on DNS metrics (default: true)
    dhcp_client_key: false            # per-MAC / client-id cf_client_key (default: false)
```

## Metric-point mapping

One or more Splunk metric points per `CloudFlowEvent`, POSTed to
`/services/collector` as newline-concatenated JSON objects:

```json
{
  "time": 1730000002.001234567,
  "source": "cloudflow:v1:wire:dns",
  "sourcetype": "cloudflow:metric",
  "host": "<envelope.source_host>",
  "index": "<config splunk.metrics_index, omitted if empty>",
  "fields": {
    "metric_name:dns.rtt_seconds": 0.001234567,
    "cf_role": "client_facing",
    "cf_service_role": "authoritative",
    "cf_rcode": "NOERROR",
    "cf_qtype": "A",
    "cf_server_ip": "192.0.2.53"
  }
}
```

`metric_name:<name>` carries the value; the other `fields` are dimensions.
`time` = `observed_time_unix_nano / 1e9` rendered with 9 decimals (the observed
wire moment, exactly like the event sink). The metric set and dimensions are
the contract in `docs/splunk-metrics.md`:

- **DNS `dns.transaction.observed`** → `dns.transactions_total` (=1) and, when
  `rtt_valid`, `dns.rtt_seconds` (=`rtt_nanos/1e9`), both dimensioned by
  `cf_role` (the leg), `cf_service_role` (the operator tier from
  `DnsTransactionEvent.service_role`, omitted if empty), `cf_rcode`, `cf_qtype`
  and `cf_server_ip`.
- **DNS `dns.query.unanswered`** → `dns.unanswered_total` (=1), by
  `cf_role`/`cf_service_role`.
- **DNS `dns.response.unmatched`** → `dns.unmatched_total` (=1), by
  `cf_role`/`cf_service_role`.
- **DHCP** → `dhcp.events_total` (=1), by `source_type` (dhcpv4/dhcpv6),
  `cf_message_type` and `cf_is_relayed`; the per-client `cf_client_key`
  (MAC / client-id / DUID) is opt-in via `dimensions.dhcp_client_key`.

Dimensions use the normalized identity from `docs/event-model.md` (role,
client/server IP, client key), not the raw nested `src_ip`. Object keys are
emitted in sorted order for stable diffs (the golden test compares structurally
regardless). An event that maps to no enabled metric is a successful no-op with
no output; only a genuinely unmappable event (missing envelope / unset payload)
is dead-lettered.

## Consumer, retry, dead-letter

Identical to the event sink (the shared spine): `XGROUP CREATE` per stream,
`XAUTOCLAIM` stale pending then `XREADGROUP`; entries validated and
protobuf-unpacked (decode failure → dead-letter `decode_error`); metric points
batched and XACKed only after a 2xx (network/429/5xx back off and retry
forever; other 4xx bisect and dead-letter poison as `hec_rejected`). Dead-letter
stream `cloudflow:v1:deadletter:sink-splunk-metrics`, `MAXLEN ~ 100000`. Metrics
are lossy by nature (a dropped point is a missing sample), but every drop is
still counted, so even metric loss is visible.

## Tests

`make test` runs the CUnit golden suite: for each `tests/golden/*.jsonl`,
rebuild its source `CloudFlowEvent` with the Python bindings
(`tests/generate_fixtures.py` → `tests/fixtures/*.pb`), run the C transform, and
structurally compare the emitted metric points against the golden — a DNS
`dns.transaction.observed` fixture (with `service_role`) and a DHCP fixture,
plus allowlist and opt-in-dimension checks. `make test-asan` runs the same suite
under `-fsanitize=address,undefined`.

## systemd

See `systemd/cloudflow-sink-splunk-metrics.service`. It reads the HEC token from
`EnvironmentFile=/etc/cloudflow/splunk-metrics.env` (a non-committed file
containing `SPLUNK_HEC_TOKEN=...`) and restarts on failure.

The unit is sandboxed (project review G4) and, being an egress *sink*, is
stricter than the capture sources: it makes only outbound HTTP(S) (to the HEC)
and Redis TCP connections, so it opens **no raw socket** — it drops every
capability with an empty `CapabilityBoundingSet=` and narrows
`RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` (no `AF_PACKET`, no
`CAP_NET_RAW`). It shares the common hardening with the sources:
`ProtectSystem=strict` + `PrivateTmp=yes` (whole FS read-only, private `/tmp`;
the daemon writes nothing to disk — logs go to journald — so no
`ReadWritePaths`), `ProtectHome`, `ProtectControlGroups`,
`ProtectKernel{Modules,Tunables}`, `LockPersonality`, `MemoryDenyWriteExecute`,
`RestrictRealtime`, `RestrictSUIDSGID`, `RestrictNamespaces`,
`SystemCallArchitectures=native`, and `SystemCallFilter=@system-service`.
