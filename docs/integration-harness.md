# Real-delivery integration harness

`scripts/run-integration-tests.sh` proves the pipeline end to end, but the
sinks run in `--stdout` mode: they *print* the HEC JSON / JSONEachRow rows
instead of delivering them, so the actual network delivery code never runs.
The real-delivery harness (`tests/integration/realdelivery/`, project review
G2) closes that gap. It stands up the real dependencies in containers and runs
the sinks in **real delivery mode**, so libcurl POST, request batching, retry,
`ack`-after-2xx, and dead-letter all execute against live services.

## What it runs

```text
                     ┌──────────── docker compose ─────────────┐
  fixtures (pcap) →  │  dhcp-source ─┐                          │
                     │  dns-source  ─┴─▶ redis (streams) ─┬─▶ splunk-sink ───▶ hecfake  │
                     │                                    ├─▶ metrics-sink ──▶ hecfake  │
                     │                                    └─▶ clickhouse-sink ▶ clickhouse
                     └──────────────────────────────────────────────────────┘
```

- **redis** (`redis:7-alpine`) — the stream transport, single node. (CloudFlow's
  Redis client is standalone-with-failover per decision D3, not cluster-aware;
  a real Redis Cluster would return `MOVED` redirects the client does not
  follow, so the harness uses a single node. Cluster support is tracked as
  separate future work.)
- **clickhouse** (`clickhouse/clickhouse-server`) — a real server. The schema
  under `sinks/cloudflow-sink-clickhouse/schema/` is auto-applied on first
  start (mounted into `/docker-entrypoint-initdb.d`), creating
  `cloudflow.events`.
- **hecfake** (`hec_fake.py`, stdlib Python) — a stand-in Splunk HEC that
  records every event/metric object it receives so the harness can assert what
  was delivered, and can optionally fail the first N requests to exercise sink
  retry.
- **the five apps** — one image (`Dockerfile`), all binaries built with the same
  `make build` CI and developers use. Sources run `--replay`; sinks run `--once`
  **without** `--stdout` (i.e. real delivery).

## What it asserts

1. The fake HEC received the expected `cloudflow:dhcpv4` and `cloudflow:dns`
   events and at least one dimensioned DNS metric point.
2. ClickHouse actually stored the rows — a real `INSERT`, queried back with
   `SELECT count() … WHERE source_type = 'dns'`.
3. Every consumer group (`sink-splunk`, `sink-splunk-metrics`,
   `sink-clickhouse`) is fully acked: `XPENDING` is 0.
4. No dead-letter entries on the happy path.

## Running it

Requires Docker and the Compose plugin. From anywhere in the repo:

```sh
tests/integration/realdelivery/run.sh
```

The script builds the app image, brings up the infra, waits for health, replays
the fixtures, delivers through the three sinks, asserts, and tears everything
down (a trap runs `docker compose down -v` on exit). It runs as the
`real-delivery` job in CI on every PR.

## Configuration

- `configs/*.yaml` — one config per app, pointed at the compose service
  hostnames (`redis:6379`, `hecfake:8088`, `clickhouse:8123`). They mirror the
  committed examples; the only deltas are hostnames and plain HTTP (the fake HEC
  and the dev ClickHouse are HTTP, so `tls_verify: false` — the sole prod
  difference is the `https://` scheme and a real certificate).
- Secrets stay in the environment (D6): the HEC token is passed via
  `CF_HARNESS_HEC_TOKEN` in `docker-compose.yml`, never in a YAML file. The fake
  HEC accepts any token. The dev ClickHouse runs as the default user with no
  password, so the ClickHouse sink omits `user_env`/`password_env`.
- Fail-injection: set `CF_HEC_FAIL_TIMES` on the `hecfake` service to make the
  first N HTTP requests return `CF_HEC_FAIL_STATUS` (default 503), exercising the
  sinks' retry path before eventual success.

## Scope and follow-ups

- The image is single-stage (build tools present at runtime) for reproducibility;
  a slimmed multi-stage runtime image is a worthwhile follow-up.
- A real Redis Cluster leg needs cluster support (`MOVED`/`ASK` + `CRC16` slot
  routing) added to `cloudflow-redis` and `cloudflow-sink-core` first — its own
  work item, revising D3.
- A delivery-failure dead-letter assertion (drive `CF_HEC_FAIL_TIMES` past the
  sink's retry budget so a live event bisects down and dead-letters) is a
  natural next assertion to add.
