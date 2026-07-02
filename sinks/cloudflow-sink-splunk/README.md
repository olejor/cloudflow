# cloudflow-sink-splunk

Redis Streams to Splunk HEC sink for CloudFlow events (WP-12, Python 3.9+,
decision D1). This document also implements the **canonical CloudFlowEvent →
Splunk JSON mapping** described in `docs/design/04-sink-splunk.md`, which is
a contract: `tools/decode-event` (WP-13) reuses it, and changing it later is
a schema change that needs a docs update.

Pipeline:

```text
XREADGROUP (group sink-splunk) -> protobuf decode -> Splunk HEC JSON
    -> HEC POST (batched) -> XACK on 2xx only
                     \-> dead-letter stream on poison events
```

Responsibilities:

- consume DHCPv4/DHCPv6 streams using the `sink-splunk` consumer group,
- decode `cloudflow.v1.CloudFlowEvent` protobuf payloads,
- convert events to Splunk-friendly JSON (see "Canonical HEC mapping" below),
- send batches to Splunk HEC with retry/backoff,
- acknowledge Redis messages only after confirmed delivery (or confirmed
  dead-lettering).

## Package layout

```text
src/cloudflow_sink_splunk/   this package
  __main__.py                 CLI: -c <config>, --stdout, --once
  config.py                   YAML config loading (schema below)
  consumer.py                 Redis consumer-group logic (XGROUP/XAUTOCLAIM/XREADGROUP/XACK)
  transform.py                canonical protobuf -> HEC JSON mapping
  hec.py                      batched Splunk HEC client (requests.Session) + retry/bisect
  deadletter.py               dead-letter stream writer
  metrics.py                  structured JSON logging + counters/stats line
src/cloudflow_pb/             generated protobuf bindings (WP-02, do not edit -- see its README)
tests/                        pytest: golden transform tests, Redis consumer
                               tests (skip cleanly without a working
                               redis-server), stub-HEC retry tests
```

## Running

```sh
# Editable install (also works via plain PYTHONPATH, see below):
pip install -e .

# Replay mode / milestone M1 check: print HEC-shaped JSON to stdout instead
# of POSTing to Splunk.
cloudflow-sink-splunk -c config/splunk-sink.example.yaml --stdout

# Process what's currently pending, then exit (used by tests and smoke checks).
cloudflow-sink-splunk -c config/splunk-sink.example.yaml --stdout --once
```

Without installing, the package also runs straight out of the checkout:

```sh
PYTHONPATH=src:src/cloudflow_pb python3 -m cloudflow_sink_splunk -c config/splunk-sink.example.yaml --stdout
```

The HEC token is **never** read from YAML. Set the environment variable
named by `splunk.hec_token_env` (default in the example config:
`SPLUNK_HEC_TOKEN`) before starting the process for real (non-`--stdout`)
delivery:

```sh
export SPLUNK_HEC_TOKEN=...
cloudflow-sink-splunk -c /etc/cloudflow/splunk-sink.yaml
```

## Configuration

Schema (see `config/splunk-sink.example.yaml`, which matches
`configs/examples/splunk-sink.yaml` in the repo root):

```yaml
service:
  name: cloudflow-sink-splunk       # required
  consumer_name: splunk-01          # required; the Redis consumer-group member name

redis:
  endpoints:                        # required, non-empty; D3: first reachable wins
    - redis01:6379
    - redis02:6379
    - redis03:6379
  streams:                          # required, non-empty
    - cloudflow:v1:wire:dhcpv4
    - cloudflow:v1:wire:dhcpv6
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
  batch_size: 500                   # default: 500
  flush_interval_ms: 1000           # default: 1000
  request_timeout_ms: 5000          # default: 5000
  tls_verify: true                  # default: true; false logs a loud warning
  include_raw_payload: false        # default: false; strips raw_dhcp_payload from HEC events
```

A token-looking string where `splunk.hec_token_env` (an environment
variable *name*) is expected -- or a literal `splunk.hec_token` key in
YAML -- is a startup error (decision D6: secrets are env-only, never in
YAML).

## Canonical HEC mapping

One HEC event per `CloudFlowEvent`, POSTed to
`/services/collector/event` as newline-concatenated JSON objects
(`transform.render_hec_line`):

```json
{
  "time": 1730000000.123456789,
  "host": "<envelope.source_host>",
  "source": "<envelope.stream_name, or the Redis stream the entry came from>",
  "sourcetype": "cloudflow:dhcpv4",
  "index": "<config splunk.index, omitted entirely if empty>",
  "event": "google.protobuf.json_format.MessageToDict(cloudflow_event, preserving_proto_field_name=True)"
}
```

Rules:

- `time` = `observed_time_unix_nano / 1e9`, always rendered with exactly 9
  decimal places (observed wire time is the Splunk event time).
- `sourcetype` comes from `splunk.sourcetypes` keyed by
  `envelope.source_type`; unknown source types fall back to
  `cloudflow:<source_type>`.
- `event` is `MessageToDict(cloudflow_event, preserving_proto_field_name=True)`
  verbatim -- bytes render as base64, enums as names, unset proto3 fields
  are omitted, and the oneof payload appears under its own field name
  (`dhcpv4_packet`, `dhcpv6_packet`), keeping Splunk search paths stable,
  e.g. `sourcetype=cloudflow:dhcpv4 event.dhcpv4_packet.decoded.message_type_name=ACK`.
- `raw_dhcp_payload` is stripped from the decoded event unless
  `splunk.include_raw_payload: true` -- it is large and base64-opaque in
  Splunk; the wire truth stays replayable from Redis.
- `--stdout` mode and golden tests use `sort_keys=True` for a stable,
  byte-for-byte comparable key order.

## Consumer behavior

- On startup: `XGROUP CREATE <stream> sink-splunk 0 MKSTREAM` for each
  configured stream (`BUSYGROUP` ignored).
- Loop: reclaim stale pending entries first (`XAUTOCLAIM`, `min-idle-time`
  60s, count-limited), then `XREADGROUP ... COUNT read_count BLOCK
  block_ms STREAMS <streams...> >`.
- Each entry's `encoding` and `schema` fields are validated
  (`protobuf` / `cloudflow.v1.CloudFlowEvent`) before the payload is
  parsed; any decode failure is dead-lettered with `reason=decode_error`
  and then XACKed (re-delivery would fail identically forever).
- Transformed events are handed to the HEC batcher; entries are XACKed
  only once their batch got a 2xx response, or after being confirmed
  dead-lettered (`reason=hec_rejected` for HTTP 4xx poison events isolated
  by batch bisection).
- SIGTERM: stop reading, flush the in-flight batch once, XACK what
  succeeded, exit 0. Unacked entries simply remain pending -- the
  at-least-once contract; Splunk-side duplicates are tolerable because
  `event_id` is preserved.

## Dead-letter stream

`cloudflow:v1:deadletter:sink-splunk`, `MAXLEN ~ 100000`, entry fields
`reason` (`decode_error` | `hec_rejected`), `origin_stream`, `origin_id`,
`error`, `payload` (verbatim original bytes). The dead-letter `XADD` must
succeed before the original entry is XACKed; if it fails, the original
entry stays pending and is retried (`deadletter.py`).

## Metrics

One structured JSON stats line on stderr per interval (Convention 7 / D8):
`splunk_delivery_total`, `splunk_delivery_errors_total`,
`splunk_retry_total`, `splunk_batch_size` (last), `splunk_delivery_latency_ms_last`
/ `splunk_delivery_latency_ms_avg`, `deadletter_total`,
`protobuf_decode_errors_total`, `redis_stream_lag` (per stream, from
`XINFO GROUPS`).

## Development

```sh
# Run the tests (no install required -- tests/conftest.py wires up sys.path):
python3 -m pytest sinks/cloudflow-sink-splunk/tests/

# Equivalent, explicit PYTHONPATH form:
PYTHONPATH=sinks/cloudflow-sink-splunk/src:sinks/cloudflow-sink-splunk/src/cloudflow_pb \
  python3 -m pytest sinks/cloudflow-sink-splunk/tests/
```

Redis-dependent tests start a private `redis-server` for the session and
skip cleanly if one cannot be found/started. Stub-HEC tests run an
in-process `http.server`; retry backoff is injected (`sleep_fn=...`) so the
suite never sleeps for real.

## systemd

See `systemd/cloudflow-sink-splunk.service`. It expects the HEC token via
`EnvironmentFile=/etc/cloudflow/splunk-sink.env` (a file containing
`SPLUNK_HEC_TOKEN=...`, not committed) and restarts on failure.
