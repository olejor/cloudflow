# WP-17 — Splunk sink rewrite in C

Supersedes the Python implementation of WP-12 (decision D1 revised — see
`00-overview.md`). The **behavioral contract of `04-sink-splunk.md` is
unchanged**: consumer-group semantics, the canonical HEC JSON mapping,
retry/poison-bisection policy, dead-letter stream, ack-only-after-delivery.
This document specifies only what changes with the language switch and how
compatibility is proven.

Rationale: the sink is the per-event CPU cost center on the delivery side
(protobuf decode + JSON build for every event). With higher-rate sources
planned (DNS), a C sink keeps that cost in line with the C source pipeline.
The Python golden files produced by WP-12 are kept and become the
cross-language contract: the C sink must produce structurally identical
output.

## What is removed, kept, added

- **Removed**: the Python package `sinks/cloudflow-sink-splunk/src/
  cloudflow_sink_splunk/` and its pytest suite, `pyproject.toml`, and the
  console-script entry point.
- **Kept**: the generated Python bindings at
  `sinks/cloudflow-sink-splunk/src/cloudflow_pb/` (tools and codegen tests
  import them; relocating them is cosmetic and deferred), the golden files
  (moved to `sinks/cloudflow-sink-splunk/tests/golden/`, same content), the
  config example, the README (rewritten), the systemd unit (ExecStart now the
  C binary).
- **Added**: C sources under `sinks/cloudflow-sink-splunk/src/` building the
  `cloudflow-sink-splunk` binary; vendored `third_party/yyjson/`
  (yyjson 0.10.0, MIT — single .c/.h, same library the legacy collector
  used); libcurl dependency (`libcurl4-openssl-dev`, pkg-config `libcurl`).

`tools/decode-event`'s `--hec` mode currently imports the Python sink's
transform module. As part of this WP it gets its own copy of the mapping
(Python, inside the tool package), validated against the same goldens — the
tool is a debug utility and stays Python.

## Architecture

Single-threaded event loop (one process per consumer; scale by running more
consumers in the group):

```text
XAUTOCLAIM (min-idle 60s) -> XREADGROUP COUNT n BLOCK 1000ms
  -> validate entry fields (schema/encoding) -> protobuf-c unpack
  -> HEC JSON via yyjson (mapping below) -> batch buffer
  -> libcurl POST (keep-alive, TLS verify on) -> 2xx: XACK batch
                                     -> 429/5xx/net: backoff 1s..30s, retry forever
                                     -> other 4xx: bisect batch, dead-letter poison, ack rest
decode failure -> dead-letter (XADD must succeed first) -> XACK
```

Components (each its own .c/.h): `config` (libyaml, same schema/env rules as
WP-12 incl. token-in-YAML startup error), `consumer` (hiredis), `transform`
(protobuf-c event -> yyjson doc), `hec` (libcurl), `deadletter`, `stats`
(counters from `04-sink-splunk.md`, periodic JSON line via cf_log), `main`
(`-c <config>`, `--stdout`, `--once`, `--version`; SIGTERM flush-once).
Links `libcloudflow-core.a` (cf_log/cf_time/cf_sync) and
`libcloudflow-codec.a`.

## Mapping compatibility

The canonical mapping is protobuf JSON semantics as produced by Python's
`MessageToDict(preserving_proto_field_name=True)`:

- proto field names verbatim (snake_case);
- defaults omitted (zero scalars, empty strings/bytes/lists, unset
  messages); the set oneof member present under its field name;
- enums as their names; `bytes` as base64; 64-bit ints as JSON strings
  (protobuf JSON convention — note `observed_time_unix_nano` etc. are
  strings in the goldens);
- HEC envelope: `time` printed with 9 decimal places; `sourcetype`/`index`/
  `host`/`source` rules per `04-sink-splunk.md`; `raw_dhcp_payload` stripped
  unless `splunk.include_raw_payload`.

Hand-written emitters cover exactly the message types in
`proto/cloudflow/v1/` (envelope, PacketObservation tree, DhcpV4PacketEvent,
DhcpV6PacketEvent, DhcpV4LeaseEvent may error as unsupported for now).
**Proof**: a test decodes each golden's source event (the fixture events are
rebuilt with the generated Python bindings by the existing scripts), runs the
C transform, and compares against the golden with a structural JSON compare
(python3 `json.loads` equality) — byte order is not part of the contract,
structure and values are. `--stdout` mode emits sorted keys so diffs stay
stable.

## Acceptance criteria

- Golden structural equality for every committed golden file.
- Consumer tests against a private redis-server (same spawn/skip pattern as
  `libs/cloudflow-redis/tests`): 100-event produce -> `--once --stdout`
  prints 100 mapped events, 0 pending after; second-consumer XAUTOCLAIM
  redelivery; poison entry -> dead-letter `reason=decode_error`, acked.
- Stub-HEC tests (python http.server harness is fine): 5xx-then-2xx retried
  and acked once; 400 on a 3-event batch isolates the poison event
  (2 delivered, 1 dead-lettered `hec_rejected`, 3 acked); token never in
  logs or stats output.
- ASan/UBSan clean over the golden + consumer tests.
- `make test` runs the sink tests; WP-14's integration flow uses this binary.
