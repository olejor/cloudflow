# ClickHouse sink (implemented)

`cloudflow-sink-clickhouse` (`sinks/cloudflow-sink-clickhouse/`, WP-CH02) writes
CloudFlow events into ClickHouse for **analytical navigation** of the data —
the relational/columnar queries that neither Splunk events nor Splunk metrics
serve well:

> "every DNS transaction from this client with SERVFAIL in the last hour,
> joined to its upstream leg", or "every DHCP lease this MAC ever held, in
> order".

Splunk events give full-text search and forensics; Splunk metrics
(`docs/splunk-metrics.md`) give cheap dashboards and alerting; ClickHouse gives
fast columnar scans, joins, and high-cardinality group-bys over the raw
firehose. The three are complementary consumers of the same streams.

## Fit

ClickHouse suits wire telemetry well: append-only, time-ordered, high-volume,
high-cardinality dimensions, cheap columnar aggregation. The sink is, like every
sink, just another consumer group (`sink-clickhouse`) on the wire streams,
reusing the consumer / `XAUTOCLAIM` / ack-after-delivery / dead-letter spine
(`libs/cloudflow-sink-core`, synergy item A1) unchanged; only the transform and
the delivery client are new — the delivery client plugs into the same
`cf_sink_delivery_t` interface the Splunk HEC client uses, and reuses the shared
batched-HTTP retry/backoff/bisection policy verbatim.

## Shape

- **Consumer group** `sink-clickhouse` on `cloudflow:v1:wire:*`.
- **Transform** (`src/row_transform.c`): decode each `CloudFlowEvent` and
  flatten it into ONE `JSONEachRow` object. A small set of common columns comes
  from the envelope and `PacketObservation` (`event_id`, `observed_time`,
  `source_type`, `source_host`, `capture_interface`, `event_type`, `src_ip`,
  `dst_ip`, `src_mac`); protocol-specific columns hold the decoded fields using
  the normalized identity from `docs/event-model.md`. A single **wide `events`
  table** holds every event: a row emits only the columns for its protocol and
  omits the rest, so JSONEachRow lets ClickHouse fill the absent protocol
  columns' `DEFAULT`s.
- **Delivery** (`src/ch_client.c`): a keep-alive libcurl handle POSTs the
  batch's newline-delimited rows to
  `<url>/?query=INSERT+INTO+<db>.<table>+FORMAT+JSONEachRow` (URL-encoded). It
  supplies only a "POST these rows once → HTTP status" primitive and drives it
  through the shared `cf_sink_http_deliver_batched` helper, so ClickHouse
  strongly-preferred large batches ride the sink's existing batch-then-flush
  model, and a bad row (ClickHouse `400`) bisects out to be dead-lettered while
  server-down / `5xx` / network errors back off and retry.
- **Auth (D6):** HTTP Basic user/password read only from the environment
  variables NAMED by `clickhouse.user_env` / `clickhouse.password_env`; a
  literal secret in YAML is a fatal startup error, and the credentials are never
  logged. TLS verification is on by default.
- **Schema:** a `ReplacingMergeTree` `events` table, partitioned by observed
  date and ordered by `(source_type, observed_time, event_id)`. Because
  `event_id` (and the `observed_time` / `source_type` derived from the same
  observation) is deterministic (D5), at-least-once redelivery reproduces the
  identical sorting-key tuple and collapses to one row on merge rather than
  duplicating — the columnar analogue of Splunk's `event_id`-based dedup.
- **Delivery guarantees:** acknowledge only after the batch `INSERT` is
  confirmed (`2xx`); transient ClickHouse unavailability backs off and retries
  (Redis is the buffer); an undecodable or unmappable event is dead-lettered
  (`cloudflow:v1:deadletter:sink-clickhouse`).

## Schema

The operator applies the DDL once (`schema/cloudflow_events.sql`; the sink never
creates tables):

```sql
CREATE TABLE cloudflow.events
(
    event_id           String,                 -- dedup key (D5)
    observed_time      DateTime64(9),          -- wire observation time
    source_type        LowCardinality(String), -- dhcpv4 | dhcpv6 | dns
    source_host        LowCardinality(String) DEFAULT '',
    capture_interface  LowCardinality(String) DEFAULT '',
    event_type         LowCardinality(String) DEFAULT '',
    src_ip             String DEFAULT '',
    dst_ip             String DEFAULT '',
    src_mac            String DEFAULT '',
    -- DHCP columns (default on non-DHCP rows)
    message_type       LowCardinality(String) DEFAULT '',
    client_key         String DEFAULT '',
    requested_address  String DEFAULT '',
    assigned_address   String DEFAULT '',
    is_relayed         UInt8  DEFAULT 0,
    -- DNS columns (default on non-DNS rows)
    qname              String DEFAULT '',
    qtype              LowCardinality(String) DEFAULT '',
    qclass             UInt16 DEFAULT 0,
    rcode              LowCardinality(String) DEFAULT '',
    rtt_seconds        Float64 DEFAULT 0,
    rtt_valid          UInt8  DEFAULT 0,
    role               LowCardinality(String) DEFAULT '',
    service_role       LowCardinality(String) DEFAULT '',
    client_ip          String DEFAULT '',
    server_ip          String DEFAULT ''
)
ENGINE = ReplacingMergeTree
PARTITION BY toDate(observed_time)
ORDER BY (source_type, observed_time, event_id);
```

`observed_time` is emitted as epoch seconds with 9 decimals (a numeric
JSONEachRow value ClickHouse reads as a `DateTime64(9)` timestamp). Protocol
columns use the normalized identity from `docs/event-model.md`: for DHCP the
`client_key` (client-id / chaddr, or the DUID hex for v6) rather than the usually
`0.0.0.0` `src_ip`; for DNS the `client_ip` / `server_ip` / `role` surfaced on
the transaction. DNS `role` and `service_role` are always-present identity
columns (empty `service_role` when the operator mapped none); the DHCP
`requested_address` / `assigned_address` are emitted only when present. Queries
that must not see a not-yet-merged duplicate use `SELECT … FINAL` or
`GROUP BY event_id`.

## Testing

`make -C sinks/cloudflow-sink-clickhouse test` runs the CUnit row-golden suite:
for a DHCPv4 DISCOVER and a DNS `dns.transaction.observed` (with `service_role`)
it structurally compares the emitted JSONEachRow row against the committed
golden. The repo integration test (`scripts/run-integration-tests.sh`) adds a
`sink-clickhouse` leg in `--stdout` mode over the replayed DNS stream (CI has no
ClickHouse server): it asserts a JSONEachRow row for the DNS transaction with the
expected `event_id` / `source_type` / `qname` / `role` / `service_role` keys and
0 pending after ack. A real-ClickHouse `INSERT` stays a documented manual step
(apply the schema, point `clickhouse.url` at the server, run without `--stdout`).

## Later ideas

A relational store (Postgres/MySQL) for *derived* state — a materialized DHCP
lease table, a DNS client inventory — is a separate, later idea that needs a
correlation/aggregation stage first; it is not planned yet and is intentionally
out of scope here.
