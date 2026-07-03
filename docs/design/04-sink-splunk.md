# cloudflow-sink-splunk

Work package WP-12. Python 3.9+ (decision D1 as originally written).

> **Status note:** WP-12 was implemented and merged, then superseded by a C
> rewrite (WP-17, `06-sink-splunk-c.md`) per the revised D1. Everything in
> this document other than the implementation language — the consumer
> semantics, the canonical HEC mapping, retry/dead-letter policy — remains
> the authoritative behavioral contract, and the golden files produced here
> are the compatibility tests for the C implementation. This document also defines the
**canonical CloudFlowEvent → Splunk JSON mapping**, which is a contract:
`tools/decode-event` (WP-13) reuses it, and changing it later is a schema
change that needs a docs update.

Pipeline per `docs/architecture.md`:

```text
XREADGROUP (group sink-splunk) -> protobuf decode -> Splunk HEC JSON
    -> HEC POST (batched) -> XACK on 2xx only
                     \-> dead-letter stream on poison events
```

## WP-12 — Splunk sink application

**Deliverables** (under `sinks/cloudflow-sink-splunk/`):

- `src/cloudflow_sink_splunk/` Python package:
  - `__main__.py` — CLI: `-c <config>`, `--stdout` (print HEC-shaped JSON
    lines instead of POSTing; used by milestone M1 and integration tests),
    `--once` (process what is pending, then exit; for tests).
  - `config.py` — loads the schema of `configs/examples/splunk-sink.yaml`
    (PyYAML). The HEC token comes **only** from the env var named by
    `splunk.hec_token_env`; a token-looking string in YAML is a startup error.
  - `consumer.py` — Redis consumer-group logic (`redis` library).
  - `transform.py` — protobuf → HEC JSON (the mapping below), importing the
    generated `cloudflow_pb` package from WP-02.
  - `hec.py` — batched HEC client (`requests.Session`).
  - `deadletter.py` — dead-letter stream writer.
  - `metrics.py` — counters + periodic structured stats log line (same
    convention as the C side: one JSON object per line on stderr).
- `pyproject.toml` (package + console script `cloudflow-sink-splunk`; deps:
  `protobuf`, `redis`, `requests`, `PyYAML` only).
- Updated `systemd/cloudflow-sink-splunk.service`
  (`Environment=`/`EnvironmentFile=` for the token, `Restart=on-failure`) and
  `sinks/cloudflow-sink-splunk/README.md`.
- `tests/` (pytest): transform golden tests, consumer/ack logic against a
  real local Redis (skipped without `CF_TEST_REDIS`), HEC client retry logic
  against a stub HTTP server.

### Consumer behavior

- On startup, `XGROUP CREATE <stream> sink-splunk 0 MKSTREAM` for each
  configured stream (ignore BUSYGROUP).
- Loop: first reclaim stale pending entries
  (`XAUTOCLAIM ... min-idle-time=60s`, count-limited) so a crashed consumer's
  messages are re-processed, then `XREADGROUP ... COUNT read_count BLOCK
  block_ms STREAMS <streams...> >`.
- Decode each entry: check `encoding == "protobuf"` and
  `schema == "cloudflow.v1.CloudFlowEvent"` fields, then parse the `payload`
  bytes. Any decode failure → dead-letter (below), then XACK the original
  (the failure is recorded; re-delivery would fail identically forever).
  Count `protobuf_decode_errors_total`.
- Transform to HEC events, hand to the HEC batcher. **XACK only entries whose
  batch got a 2xx** (or after confirmed dead-lettering). Batches keep the
  originating `(stream, entry_id)` list for exactly this purpose.
- Shutdown (SIGTERM): stop reading, flush the in-flight batch once, XACK what
  succeeded, exit 0. Unacked entries simply remain pending — that is the
  at-least-once contract; Splunk-side duplicates are tolerable because
  `event_id` is preserved.

### Canonical HEC mapping

One HEC event per CloudFlowEvent, POSTed to
`/services/collector/event` as newline-concatenated JSON objects:

```json
{
  "time": 1730000000.123456789,
  "host": "<envelope.source_host>",
  "source": "<envelope.stream_name or the stream the entry came from>",
  "sourcetype": "cloudflow:dhcpv4",
  "index": "<config splunk.index, omit if empty>",
  "event": {
    "event_id": "...",
    "schema_version": 1,
    "source_type": "dhcpv4",
    "...": "every envelope field, snake_case, defaults omitted",
    "dhcpv4_packet": { "...decoded payload..." }
  }
}
```

Rules:

- `time` = `observed_time_unix_nano / 1e9`, formatted with 9 decimal places
  (observed wire time is the Splunk event time — `docs/splunk-output.md`).
- `sourcetype` from config `splunk.sourcetypes` keyed by
  `envelope.source_type`; unknown source types use
  `cloudflow:<source_type>`.
- `event` = `google.protobuf.json_format.MessageToDict(cloudflow_event,
  preserving_proto_field_name=True)` — so field names match the `.proto`
  exactly. `bytes` fields therefore render as base64 (protobuf JSON
  convention); enums as their names. Do not hand-roll the conversion.
- The oneof payload appears under its field name (`dhcpv4_packet`,
  `dhcpv6_packet`), which keeps Splunk search paths stable, e.g.
  `sourcetype=cloudflow:dhcpv4 event.dhcpv4_packet.decoded.message_type_name=ACK`.
- Strip `raw_dhcp_payload` from the JSON by default (config
  `splunk.include_raw_payload: false`) — it is large and base64-opaque in
  Splunk; the wire truth remains replayable from Redis.

### HEC delivery and retry

- Batch by `splunk.batch_size` or `splunk.flush_interval_ms`, whichever first.
- `requests.Session` with keep-alive; timeout `splunk.request_timeout_ms`;
  TLS verification on (config `splunk.tls_verify: true` default; setting it
  false logs a loud warning).
- Retry policy per batch: network errors, timeouts, HTTP 429 and 5xx →
  exponential backoff 1 s doubling to 30 s cap, retrying indefinitely
  (consumption pauses — Redis is the buffer; that is by design, see
  `docs/failure-modes.md`). HTTP 4xx other than 429 → the batch is bisected
  to isolate poison events (recursive split, floor batch=1); poison events
  are dead-lettered + XACKed, the rest delivered normally.
- Counters: `splunk_delivery_total`, `splunk_delivery_errors_total`,
  `splunk_retry_total`, `splunk_batch_size` (last), 
  `splunk_delivery_latency_ms` (last/avg), `deadletter_total`,
  `redis_stream_lag` (per stream: `XINFO STREAM` last id vs. last delivered).

### Dead-letter stream

Stream `cloudflow:v1:deadletter:sink-splunk` (add to `docs/redis-streams.md`
and `configs/examples/redis.yaml`). Entry fields:

```text
reason        decode_error | hec_rejected
origin_stream <stream name>
origin_id     <redis entry id>
error         <short message, e.g. HTTP status + body prefix>
payload       <original payload bytes, verbatim>
```

MAXLEN ~ 100000. Dead-lettering must succeed before the original entry is
XACKed; if the dead-letter XADD itself fails, the original stays pending and
will be retried (at-least-once, never silent loss).

**Acceptance criteria.**

- Golden tests: for each fixture-derived packed `CloudFlowEvent` (produced by
  the WP-06/07 fixture round-trip binaries, or by `generate_fixtures.py`
  building events directly with the Python bindings until those land), the
  HEC JSON matches a committed golden file byte-for-byte (stable key order:
  `json.dumps(..., sort_keys=True)` in `--stdout` mode).
- Against local Redis: producing 100 events then running `--once --stdout`
  prints 100 mapped events and leaves 0 pending after ack; killing the sink
  mid-batch and re-running re-delivers unacked entries exactly (XAUTOCLAIM
  path covered by a second consumer name).
- Stub-HEC tests: 5xx then 2xx → retried, acked once; 400 on a 3-event batch
  with one poison → 2 delivered, 1 dead-lettered with `reason=hec_rejected`,
  all 3 acked; token never appears in logs.
- Milestone M1 check: `--stdout` mode consumes the event produced by the
  source's `--replay` run and prints readable JSON.
