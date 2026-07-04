# ClickHouse sink (designed, future)

`cloudflow-sink-clickhouse` is a designed, not-yet-implemented sink that writes
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
high-cardinality dimensions, cheap columnar aggregation. It is already noted as
a candidate sink in the project's extensibility list. The sink is, like every
sink, just another consumer group (`sink-clickhouse`) on the wire streams,
reusing the consumer / `XAUTOCLAIM` / ack-after-delivery / dead-letter spine;
only the transform and the delivery client are new.

## Shape

- **Consumer group** `sink-clickhouse` on `cloudflow:v1:wire:*`.
- **Transform**: decode each `CloudFlowEvent` and flatten it into a row. A
  small set of common columns comes from the envelope and `PacketObservation`
  (`event_id`, `observed_time`, `source_type`, `source_host`,
  `capture_interface`, `src_ip`, `dst_ip`, `src_mac`, the normalized
  identity from `docs/event-model.md`); protocol-specific columns hold the
  decoded fields (DHCP message type / client key / lease address; DNS qname /
  qtype / rcode / rtt / role). Options are the wide-table-per-protocol vs.
  one-events-table-with-nested-columns choice to settle at implementation.
- **Delivery**: batched `INSERT` (ClickHouse native protocol or HTTP with
  async inserts) — ClickHouse strongly prefers large batches, which aligns
  with the sink's existing batch-then-flush model.
- **Schema**: `MergeTree` family, partitioned by observed date, ordered by
  `(source_type, observed_time, …)` for time-range + protocol scans. Use
  `ReplacingMergeTree` keyed on `event_id` so at-least-once redelivery (the
  same deterministic `event_id`, D5) collapses to one row rather than
  duplicating — the columnar analogue of Splunk's `event_id`-based dedup.
- **Delivery guarantees**: acknowledge only after the batch `INSERT` is
  confirmed; transient ClickHouse unavailability backs off and retries (Redis
  is the buffer); an undecodable event is dead-lettered
  (`cloudflow:v1:deadletter:sink-clickhouse`).

## Roadmap

Deferred until after the DNS source is implemented. DNS is the volume and the
high-cardinality, join-heavy data (client ↔ transaction ↔ upstream leg) that
makes a columnar analytics store earn its keep; standing it up against
DHCP-only traffic would be premature. This document fixes the intended shape so
the work is well-scoped when the time comes.

A relational store (Postgres/MySQL) for *derived* state — a materialized DHCP
lease table, a DNS client inventory — is a separate, later idea that needs a
correlation/aggregation stage first; it is not planned yet and is intentionally
out of scope here.
