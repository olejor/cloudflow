# cloudflow-sink-splunk

Redis Streams to Splunk HEC sink for CloudFlow events. C11 (decision D1,
`docs/architecture.md`). The **canonical CloudFlowEvent → Splunk HEC JSON
mapping** and the consumer/retry/dead-letter behavior are the contract
documented in `docs/splunk-output.md`; the golden files in `tests/golden/`
are what the C transform is proven against.

Pipeline:

```text
XAUTOCLAIM (min-idle 60s) -> XREADGROUP (group sink-splunk)
    -> protobuf-c decode -> HEC JSON (yyjson) -> HEC POST (libcurl, batched)
        -> XACK on 2xx only
         \-> dead-letter stream on poison events (decode / HTTP 4xx)
```

Responsibilities:

- consume DHCPv4/DHCPv6 streams using the `sink-splunk` consumer group;
- decode `cloudflow.v1.CloudFlowEvent` protobuf payloads;
- convert events to Splunk HEC JSON (see "Canonical HEC mapping");
- POST batches to Splunk HEC with retry/backoff and poison bisection;
- acknowledge Redis entries only after confirmed delivery (or confirmed
  dead-lettering).

## Layout

```text
src/
  main.c          CLI: -c <config>, --stdout, --once, --version; SIGTERM flush-once
  config.{c,h}    YAML config loading (libyaml); env-only HEC token (D6)
  consumer.{c,h}  Redis consumer group (hiredis): XGROUP/XAUTOCLAIM/XREADGROUP/XACK
  transform.{c,h} protobuf-c CloudFlowEvent -> yyjson HEC JSON (the mapping)
  hec.{c,h}       batched Splunk HEC client (libcurl) + retry/backoff/bisect
  deadletter.{c,h}dead-letter stream writer
  stats.{c,h}     counters + periodic structured stats line
src/cloudflow_pb/ generated Python bindings (WP-02) -- kept for tools + the
                  golden generator; not used by the C binary
tests/            CUnit suites + golden files + the Python golden generator
config/           example config
systemd/          unit file
Makefile          build/cloudflow-sink-splunk; `all test test-asan clean`
```

## Building

Depends on: `libcloudflow-core.a`, `libcloudflow-codec.a`, the vendored
`third_party/yyjson`, and the system libraries hiredis, libcurl, libyaml,
libprotobuf-c (all via `pkg-config`).

```sh
make -C sinks/cloudflow-sink-splunk all       # -> build/cloudflow-sink-splunk
make -C sinks/cloudflow-sink-splunk test       # CUnit suites (see below)
make -C sinks/cloudflow-sink-splunk test-asan  # same suites under ASan/UBSan
make -C sinks/cloudflow-sink-splunk clean
```

## Running

```sh
# Replay / milestone check: print HEC-shaped JSON to stdout instead of POSTing.
build/cloudflow-sink-splunk -c config/splunk-sink.example.yaml --stdout --once

# Real delivery to Splunk HEC (token from the environment, see below):
export SPLUNK_HEC_TOKEN=...
build/cloudflow-sink-splunk -c /etc/cloudflow/splunk-sink.yaml
```

Flags: `-c/--config PATH` (required), `--stdout` (print HEC JSON lines instead
of POSTing), `--once` (drain what is pending, then exit), `--version`.
`SIGTERM`/`SIGINT` flush the in-flight batch once, ack what succeeded, then
exit (at-least-once; unacked entries stay pending).

The HEC token is **never** read from YAML. Set the environment variable named
by `splunk.hec_token_env` (default `SPLUNK_HEC_TOKEN`). A token-looking string
where an env-var *name* is expected, or a literal `splunk.hec_token` key in
YAML, is a fatal startup error (decision D6). The token is never logged.

## Configuration

Schema (see `config/splunk-sink.example.yaml`, identical to
`configs/examples/splunk-sink.yaml`):

```yaml
service:
  name: cloudflow-sink-splunk       # required
  consumer_name: splunk-01          # required; the consumer-group member name

redis:
  endpoints:                        # required, non-empty; D3: first reachable wins
    - redis01:6379
  streams:                          # required, non-empty
    - cloudflow:v1:wire:dhcpv4
    - cloudflow:v1:wire:dhcpv6
    - cloudflow:v1:wire:dns
  consumer_group: sink-splunk       # default: sink-splunk
  read_count: 100                   # default: 100
  block_ms: 1000                    # default: 1000

splunk:
  hec_url: https://splunk.example.com:8088/services/collector/event   # required
  hec_token_env: SPLUNK_HEC_TOKEN   # required; names an env var, never a literal token
  index: network                    # default: "" (omitted from HEC events when empty)
  sourcetypes:                      # default: {}; unmatched source_type -> cloudflow:<source_type>
    dhcpv4: cloudflow:dhcpv4
    dhcpv6: cloudflow:dhcpv6
    dns: cloudflow:dns
  batch_size: 500                   # default: 500
  flush_interval_ms: 1000           # default: 1000
  request_timeout_ms: 5000          # default: 5000
  tls_verify: true                  # default: true; false logs a loud warning
  include_raw_payload: false        # default: false; strips raw_dhcp_payload from HEC events
```

## Canonical HEC mapping

One HEC event per `CloudFlowEvent`, POSTed to `/services/collector/event` as
newline-concatenated JSON objects:

```json
{
  "time": 1730000000.123456789,
  "host": "<envelope.source_host>",
  "source": "<envelope.stream_name, or the Redis stream the entry came from>",
  "sourcetype": "cloudflow:dhcpv4",
  "index": "<config splunk.index, omitted entirely if empty>",
  "event": { "...MessageToDict(preserving_proto_field_name=True)..." }
}
```

Rules (reproducing protobuf JSON / `MessageToDict` semantics exactly):

- `time` = `observed_time_unix_nano / 1e9`, rendered with exactly 9 decimals;
- proto field names verbatim (snake_case); proto3 defaults omitted; the set
  oneof payload appears under its field name
  (`dhcpv4_packet`/`dhcpv6_packet`/`dns_transaction`);
- enums as their `.proto` names; `bytes` as base64; 64-bit integers as JSON
  strings; 32-bit integers/bools/floats as JSON numbers/bools;
- `sourcetype` from `splunk.sourcetypes` keyed by `envelope.source_type`,
  falling back to `cloudflow:<source_type>`;
- `raw_dhcp_payload` is stripped unless `splunk.include_raw_payload: true`;
- object keys are emitted in sorted order for stable diffs (the golden test
  compares structurally regardless of key order).

## Consumer, retry, dead-letter

- Startup: `XGROUP CREATE <stream> <group> 0 MKSTREAM` per stream (BUSYGROUP
  ignored). Loop: `XAUTOCLAIM` stale pending (min-idle 60s) then `XREADGROUP
  ... COUNT read_count BLOCK block_ms ... >`.
- Each entry's `encoding`/`schema` are validated (`protobuf` /
  `cloudflow.v1.CloudFlowEvent`) before the payload is unpacked; any decode
  failure is dead-lettered (`reason=decode_error`) then XACKed.
- Retry per batch: network/timeout/HTTP 429/5xx back off 1s→30s and retry
  forever (Redis is the buffer). Other 4xx bisect the batch to isolate poison
  events, which are dead-lettered (`reason=hec_rejected`) and XACKed; the rest
  are delivered.
- Dead-letter stream `cloudflow:v1:deadletter:sink-splunk`, `MAXLEN ~ 100000`,
  fields `reason`/`origin_stream`/`origin_id`/`error`/`payload`. The XADD must
  succeed before the origin entry is XACKed (never silent loss).

## Metrics

One structured JSON `stats` line on stderr per interval (Convention 7 / D8):
`splunk_delivery_total`, `splunk_delivery_errors_total`, `splunk_retry_total`,
`deadletter_total`, `protobuf_decode_errors_total`, `splunk_batch_size`,
`splunk_delivery_latency_ms`. The token never appears in any log line.

## Tests

`make test` runs three CUnit suites (each skips cleanly if its dependency is
absent):

- **golden compatibility** — for each `tests/golden/*.json`, rebuild its
  source `CloudFlowEvent` with the Python bindings
  (`tests/generate_fixtures.py` → `tests/fixtures/*.pb`), run the C transform,
  and structurally compare against the golden;
- **consumer** — private `redis-server`: 100 events → `--once` prints 100
  mapped events with 0 pending; second-consumer XAUTOCLAIM redelivery; poison
  entry → dead-letter `decode_error`, acked;
- **HEC** — a python `http.server` stub: 5xx-then-2xx retried and delivered
  once; 400 on a 3-event batch bisected (2 delivered, 1 dead-lettered
  `hec_rejected`); token sent on the wire but never logged.

`make test-asan` runs the same suites under `-fsanitize=address,undefined`.

## systemd

See `systemd/cloudflow-sink-splunk.service`. It reads the HEC token from
`EnvironmentFile=/etc/cloudflow/splunk-sink.env` (a non-committed file
containing `SPLUNK_HEC_TOKEN=...`) and restarts on failure.
