# Splunk output

`cloudflow-sink-splunk` is a C11 service that consumes `CloudFlowEvent`s from
Redis Streams and delivers them to Splunk HEC as JSON. This document is the
authoritative reference for the sink: its consumer semantics, the
**canonical CloudFlowEvent → Splunk HEC mapping** (a stable contract — the
`decode-event` debug tool's `--hec` mode reuses the same rules, and changing
them is a schema change), and its retry/dead-letter behavior.

This sink delivers to Splunk's **event** index (full-fidelity, searchable
JSON). A sibling **metrics** sink — same spine, different transform, its own
consumer group — delivers rates and latency distributions to Splunk's metrics
index; it is designed in `docs/splunk-metrics.md`. Both, and the designed
ClickHouse sink (`docs/clickhouse-sink.md`), are independent consumers of the
same streams (see the sinks table in `docs/architecture.md`).

Pipeline:

```text
XAUTOCLAIM (min-idle 60s) -> XREADGROUP (group sink-splunk) COUNT n BLOCK block_ms
  -> validate entry fields (schema/encoding) -> protobuf-c unpack
  -> HEC JSON (yyjson) -> batch buffer
  -> libcurl POST (keep-alive, TLS verify on) -> 2xx: XACK batch
                                     -> 429/5xx/net: backoff 1s..30s, retry forever
                                     -> other 4xx: bisect batch, dead-letter poison, ack rest
decode failure -> dead-letter (XADD must succeed first) -> XACK
```

## Architecture

Single-threaded event loop; scale by running more consumers in the
`sink-splunk` group. Components, each its own `.c/.h` under
`sinks/cloudflow-sink-splunk/src/`:

- `config` — libyaml loader for `configs/examples/splunk-sink.yaml` (D6, see
  `docs/architecture.md`). The HEC token comes **only** from the env var
  named by `splunk.hec_token_env`; a token-looking literal in YAML is a
  startup error.
- `consumer` — hiredis consumer-group logic.
- `transform` — `protobuf-c` event → yyjson document (the mapping below).
- `hec` — libcurl HEC client (keep-alive, batched POST, retry).
- `deadletter` — dead-letter stream writer.
- `stats` — counters + a periodic structured JSON stats line via `cf_log`;
  the HEC token is never logged.
- `main` — CLI `-c <config>`, `--stdout` (print HEC JSON instead of
  POSTing), `--once` (process pending, then exit), `--version`; SIGTERM
  flushes once.

Links `libcloudflow-core.a` (`cf_log`/`cf_time`/`cf_sync`),
`libcloudflow-codec.a` (generated protobuf-c), and vendored
`third_party/yyjson/` (yyjson 0.10.0, MIT). External deps: hiredis, libcurl,
libyaml, protobuf-c. The systemd unit runs the binary with an
`EnvironmentFile` for the token and `Restart=on-failure`.

## Consumer behavior

- On startup, `XGROUP CREATE <stream> sink-splunk 0 MKSTREAM` for each
  configured stream (ignore `BUSYGROUP`).
- Loop: first reclaim stale pending entries (`XAUTOCLAIM ...
  min-idle-time=60s`, count-limited) so a crashed consumer's messages are
  re-processed, then `XREADGROUP ... COUNT read_count BLOCK block_ms STREAMS
  <streams...> >`.
- Validate each entry's `encoding == "protobuf"` and
  `schema == "cloudflow.v1.CloudFlowEvent"` fields, then unpack the `payload`
  bytes. Any decode failure → dead-letter (below), then XACK the original (a
  re-delivery would fail identically forever). Counted as
  `protobuf_decode_errors_total`.
- Transform to HEC events and hand them to the HEC batcher. **XACK only
  entries whose batch got a 2xx** (or after confirmed dead-lettering);
  batches keep the originating `(stream, entry_id)` list for exactly this
  purpose.
- Shutdown (SIGTERM): stop reading, flush the in-flight batch once, XACK
  what succeeded, exit 0. Unacked entries stay pending — the at-least-once
  contract; Splunk-side duplicates are tolerable because `event_id` is
  preserved and deterministic (D5, `docs/architecture.md`).

## Canonical HEC mapping

One HEC event per `CloudFlowEvent`, POSTed to `/services/collector/event` as
newline-concatenated JSON objects:

```json
{
  "time": 1730000000.123456789,
  "host": "<envelope.source_host>",
  "source": "<envelope.stream_name, or the stream the entry came from>",
  "sourcetype": "cloudflow:dhcpv4",
  "index": "<config splunk.index, omitted if empty>",
  "event": {
    "event_id": "...",
    "source_type": "dhcpv4",
    "...": "every envelope field, snake_case, defaults omitted",
    "dhcpv4_packet": { "...decoded payload..." }
  }
}
```

Rules — this is the contract:

- `time` = `observed_time_unix_nano / 1e9`, rendered with exactly 9 decimal
  places as a JSON number (observed wire time is the Splunk event time —
  this is why sources preserve it separately from ingest time).
- `host` = `source_host`; `source` = `stream_name` (falling back to the
  entry's stream); `index` from config, omitted if empty.
- `sourcetype` from `splunk.sourcetypes` keyed by `source_type`; unknown
  types fall back to `cloudflow:<source_type>`. The current mapping covers
  `cloudflow:dhcpv4` and `cloudflow:dhcpv6`.
- `event` = protobuf JSON of the whole `CloudFlowEvent` with
  `preserve_proto_field_name` semantics — field names match the `.proto`
  exactly, `bytes` render as base64, enums as their names, 64-bit ints as
  JSON strings, defaults (zero scalars / empty strings, bytes, lists / unset
  messages) omitted. The reference semantics are Python's
  `MessageToDict(preserving_proto_field_name=True)`; the C transform
  (yyjson) reproduces them, verified structurally against golden files.
- The set oneof payload appears under its field name (`dhcpv4_packet`,
  `dhcpv6_packet`, and — once the DNS source lands — `dns_transaction`),
  keeping Splunk search paths stable, e.g.
  `sourcetype=cloudflow:dhcpv4 event.dhcpv4_packet.decoded.message_type_name=ACK`.
- Large raw payload bytes (`raw_dhcp_payload`) are stripped by default
  (`splunk.include_raw_payload: false`) — base64-opaque in Splunk, and the
  wire truth stays replayable from Redis.
- Do not index opaque protobuf bytes directly; the mapping above is the only
  supported Splunk-side representation of an event.

`--stdout` mode emits sorted keys so output is deterministic; golden
comparison is structural (`json.loads` equality), not byte-exact.

## HEC delivery and retry

- Batch by `splunk.batch_size` or `splunk.flush_interval_ms`, whichever
  first.
- libcurl session with keep-alive; timeout `splunk.request_timeout_ms`; TLS
  verification on (`splunk.tls_verify: true` default; setting it false logs
  a loud warning).
- Retry policy per batch: network errors, timeouts, HTTP 429 and 5xx →
  backoff 1 s doubling to a 30 s cap, retrying **indefinitely**
  (consumption pauses — Redis is the durable buffer by design, see
  `docs/failure-modes.md`). HTTP 4xx other than 429 → bisect the batch
  (recursive split, floor batch=1) to isolate poison events; poison events
  are dead-lettered and XACKed, the rest delivered normally.
- Counters: `splunk_delivery_total`, `splunk_delivery_errors_total`,
  `splunk_retry_total`, `splunk_batch_size` (last),
  `splunk_delivery_latency_ms`, `deadletter_total`, `redis_stream_lag`
  (per stream: `XINFO STREAM` last id vs. last delivered).

## Dead-letter stream

Stream `cloudflow:v1:deadletter:sink-splunk` (also in
`docs/redis-streams.md` and `configs/examples/redis.yaml`). Entry fields:

```text
reason        decode_error | hec_rejected
origin_stream <stream name>
origin_id     <redis entry id>
error         <short message, e.g. HTTP status + body prefix>
payload       <original payload bytes, verbatim>
```

`MAXLEN ~ 100000`. Dead-lettering must succeed **before** the origin entry
is XACKed; if the dead-letter XADD itself fails, the origin stays pending
and is retried — never silent loss.

## Testing

- Golden compatibility: for each committed golden file (built from a
  fixture `CloudFlowEvent`), the transform output is structurally equal —
  see `sinks/cloudflow-sink-splunk/tests/test_transform_golden.c` and
  `tests/golden/`.
- Against a private redis-server: 100 events → `--once --stdout` prints 100
  mapped events, 0 pending after ack; a second consumer name exercises the
  XAUTOCLAIM redelivery path; a poison entry is dead-lettered
  (`reason=decode_error`) and acked
  (`sinks/cloudflow-sink-splunk/tests/test_consumer.c`).
- Stub-HEC tests (`tests/test_hec.c`): 5xx-then-2xx retried and acked once;
  a 3-event batch with one poison event under HTTP 400 bisects to 2
  delivered + 1 dead-lettered (`reason=hec_rejected`), all acked; the token
  never appears in logs or stats output.
- ASan/UBSan clean over the golden + consumer tests (`make test-asan`).
- `scripts/run-integration-tests.sh` drives this binary end to end against
  the real source and a real Redis; see `docs/building-and-testing.md`.
