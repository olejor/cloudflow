# cloudflow-sink-clickhouse

Redis Streams to **ClickHouse** columnar sink for CloudFlow. C11 (decision D1,
`docs/architecture.md`). It reads the same wire streams as the Splunk sinks and
writes each CloudFlow event as one row into a wide ClickHouse `events` table, for
the relational/columnar queries that neither Splunk events nor Splunk metrics
serve well — fast scans, joins and high-cardinality group-bys over the raw
firehose (`docs/clickhouse-sink.md`).

It is complementary to the Splunk sinks, not an alternative: a third consumer
group (`sink-clickhouse`) on the same streams, so it reuses the entire sink spine
(`libs/cloudflow-sink-core`) unchanged — only the transform and the delivery
client are ClickHouse-specific.

Pipeline:

```text
XAUTOCLAIM (min-idle 60s) -> XREADGROUP (group sink-clickhouse)
    -> protobuf-c decode -> one JSONEachRow row (yyjson)
        -> batched INSERT (libcurl, HTTP JSONEachRow) -> XACK on 2xx only
         \-> dead-letter stream on poison events (decode / ClickHouse 400)
```

## Layout

The generic sink spine — the consumer group, dead-letter writer, base
config/stats, the run loop, and the pluggable delivery interface with its
reusable batched-HTTP retry/backoff/bisection helper — lives in
`libs/cloudflow-sink-core` (synergy item A1) and is shared with the Splunk sinks.
This app keeps only the ClickHouse-specific pieces:

```text
src/
  main.c                thin CLI: parse config, build the ClickHouse client,
                        supply the row transform, call cf_sink_run; --stdout, --once, --version
  config.{c,h}          ClickHouse config (url/database/table, creds env-var names,
                        batch/flush, tls_verify), layered on cf_sink_config
  row_transform.{c,h}   protobuf-c CloudFlowEvent -> one JSONEachRow object (yyjson)
  ch_client.{c,h}       keep-alive libcurl batched-INSERT client; a ch_post_once
                        primitive driven through the shared retry/bisection helper;
                        exposed as a cf_sink_delivery_t
schema/cloudflow_events.sql  the ReplacingMergeTree DDL (applied by the operator)
tests/                  golden row suite + goldens + Python golden generator
config/                 example config
systemd/                unit file
Makefile                build/cloudflow-sink-clickhouse; `all test test-asan clean`
```

## Building

Depends on: `libcloudflow-sink-core.a`, `libcloudflow-core.a`,
`libcloudflow-codec.a`, the vendored `third_party/yyjson`, and the system
libraries hiredis, libcurl, libyaml, libprotobuf-c (all via `pkg-config`).

```sh
make -C sinks/cloudflow-sink-clickhouse all       # -> build/cloudflow-sink-clickhouse
make -C sinks/cloudflow-sink-clickhouse test      # CUnit row-golden suite
make -C sinks/cloudflow-sink-clickhouse test-asan # same suite under ASan/UBSan
make -C sinks/cloudflow-sink-clickhouse clean
```

## Running

The operator applies the schema once (the sink never creates tables):

```sh
clickhouse-client --database cloudflow < schema/cloudflow_events.sql
```

Then run the sink:

```sh
# Replay / milestone check: print JSONEachRow rows to stdout instead of inserting
# (no client or credentials needed).
build/cloudflow-sink-clickhouse -c config/clickhouse-sink.example.yaml --stdout --once

# Real delivery to ClickHouse (credentials from the environment, see below):
export CLICKHOUSE_USER=cloudflow CLICKHOUSE_PASSWORD=...
build/cloudflow-sink-clickhouse -c /etc/cloudflow/clickhouse-sink.yaml
```

Flags: `-c/--config PATH` (required), `--stdout` (print the JSONEachRow rows
instead of inserting), `--once` (drain what is pending, then exit), `--version`.
`SIGTERM`/`SIGINT` flush the in-flight batch once, ack what succeeded, then exit
(at-least-once; unacked entries stay pending).

Credentials are **never** read from YAML. Set the environment variables named by
`clickhouse.user_env` / `clickhouse.password_env` (HTTP Basic auth). A
secret-looking string where an env-var *name* is expected, or a literal
`clickhouse.password` key in YAML, is a fatal startup error (decision D6). The
credentials are never logged. Omit both env-name keys for a ClickHouse that needs
no auth. TLS verification is on by default; disabling it logs a loud warning.

## Configuration

Schema (see `config/clickhouse-sink.example.yaml`, identical to
`configs/examples/clickhouse-sink.yaml`). The `service` and `redis` sections are
the shared sink topology; the `clickhouse` section is this sink's:

```yaml
clickhouse:
  url: https://clickhouse.example.com:8443   # HTTP interface base URL
  database: cloudflow
  table: events
  user_env: CLICKHOUSE_USER                  # env var NAME (D6), not a literal
  password_env: CLICKHOUSE_PASSWORD          # env var NAME (D6), not a literal
  batch_size: 10000                          # large INSERT batches (ClickHouse prefers them)
  flush_interval_ms: 1000
  request_timeout_ms: 5000
  tls_verify: true
```

## Row mapping

One JSONEachRow object per `CloudFlowEvent`, POSTed (batched) to
`INSERT INTO <database>.<table> FORMAT JSONEachRow`. One wide `events` table
holds every event; a row emits only the columns relevant to its protocol and
OMITS the rest, so ClickHouse fills the absent protocol columns' DEFAULTs. Example
DNS row:

```json
{
  "event_id": "ab12cd34ef56ab12cd34ef56ab12cd34",
  "observed_time": 1730000002.000000000,
  "source_type": "dns",
  "source_host": "dns-source-01.example.net",
  "capture_interface": "eth0",
  "event_type": "dns.transaction.observed",
  "src_ip": "192.0.2.100",
  "dst_ip": "192.0.2.53",
  "src_mac": "02:00:00:00:00:01",
  "qname": "www.example.com",
  "qtype": "A",
  "qclass": 1,
  "rcode": "NOERROR",
  "rtt_seconds": 0.001234567,
  "rtt_valid": 1,
  "role": "client_facing",
  "service_role": "authoritative",
  "client_ip": "192.0.2.100",
  "server_ip": "192.0.2.53"
}
```

Columns (the contract; `schema/cloudflow_events.sql` is the matching DDL):

- **common (every row):** `event_id`, `observed_time` (a `DateTime64(9)`
  rendered as epoch seconds with 9 decimals), `source_type`, `source_host`,
  `capture_interface`, `event_type`, `src_ip`, `dst_ip`, `src_mac`.
- **DHCP:** `message_type`, `client_key` (the normalized client id / chaddr, or
  the DUID hex for v6), `requested_address` / `assigned_address` (when present),
  `is_relayed`.
- **DNS:** `qname`, `qtype`, `qclass`, `rcode`, `rtt_seconds`, `rtt_valid`,
  `role` (the leg), `service_role` (the operator tier, when mapped), `client_ip`,
  `server_ip`.

Protocol columns use the normalized identity from `docs/event-model.md` (client
key / client IP / role), not the raw nested `src_ip`. Only a genuinely
unmappable event (missing envelope / unset payload) is dead-lettered.

## Dedup — ReplacingMergeTree

`events` is a `ReplacingMergeTree` ordered by `(source_type, observed_time,
event_id)` and partitioned by `toDate(observed_time)`. Delivery is at-least-once
(D5): because `event_id` (and the `observed_time`/`source_type` derived from the
same observation) is deterministic, a redelivered event reproduces the identical
sorting-key tuple and collapses to one row on merge — the columnar analogue of
the Splunk sinks' `event_id` dedup. Queries that must not see a not-yet-merged
duplicate use `SELECT ... FINAL` or `GROUP BY event_id`.

## Consumer, retry, dead-letter

Identical to the Splunk sinks (the shared spine): `XGROUP CREATE` per stream,
`XAUTOCLAIM` stale pending then `XREADGROUP`; entries validated and
protobuf-unpacked (decode failure → dead-letter `decode_error`); rows batched and
XACKed only after a 2xx. The ClickHouse client supplies only a "POST these rows
once → HTTP status" primitive and drives it through the shared batched-HTTP
policy: a bad row (ClickHouse 400) recursively bisects the batch to isolate and
dead-letter the poison row, while server down / 5xx / network errors back off (1s
doubling to a 30s cap) and retry forever (Redis is the durable buffer).
Dead-letter stream `cloudflow:v1:deadletter:sink-clickhouse`.

## Tests

`make test` runs the CUnit golden suite: for each `tests/golden/*.jsonl`, rebuild
its source `CloudFlowEvent` with the shared Python bindings
(`tests/generate_fixtures.py` → `tests/fixtures/*.pb`), run the C transform, and
structurally compare the emitted row against the golden — a DNS
`dns.transaction.observed` (with `service_role`) and a DHCPv4 DISCOVER.
`make test-asan` runs the same suite under `-fsanitize=address,undefined`. The
repo-level integration test (`scripts/run-integration-tests.sh`) adds a
`--stdout` leg over the replayed streams (CI has no ClickHouse server); a real
ClickHouse INSERT is a documented manual step.

## systemd

See `systemd/cloudflow-sink-clickhouse.service`. It reads the credentials from
`EnvironmentFile=/etc/cloudflow/clickhouse-sink.env` (a non-committed file
containing `CLICKHOUSE_USER=...` / `CLICKHOUSE_PASSWORD=...`) and restarts on
failure.

The unit is sandboxed (project review G4) and, being an egress *sink*, is
stricter than the capture sources: it makes only outbound HTTP(S) (to
ClickHouse) and Redis TCP connections, so it opens **no raw socket** — it drops
every capability with an empty `CapabilityBoundingSet=` and narrows
`RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` (no `AF_PACKET`, no
`CAP_NET_RAW`). It shares the common hardening with the sources:
`ProtectSystem=strict` + `PrivateTmp=yes` (whole FS read-only, private `/tmp`;
the daemon writes nothing to disk — logs go to journald — so no
`ReadWritePaths`), `ProtectHome`, `ProtectControlGroups`,
`ProtectKernel{Modules,Tunables}`, `LockPersonality`, `MemoryDenyWriteExecute`,
`RestrictRealtime`, `RestrictSUIDSGID`, `RestrictNamespaces`,
`SystemCallArchitectures=native`, and `SystemCallFilter=@system-service`.
