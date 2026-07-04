-- CloudFlow ClickHouse sink schema (WP-CH02, docs/clickhouse-sink.md).
--
-- One wide `events` table holds every wire event. cloudflow-sink-clickhouse
-- writes rows into it with `INSERT INTO <db>.events FORMAT JSONEachRow`; the row
-- transform (src/row_transform.c) emits only the columns relevant to each
-- event's protocol and OMITS the rest, so ClickHouse fills the DEFAULTs below
-- for the absent protocol columns (JSONEachRow treats a missing key as default).
--
-- ReplacingMergeTree gives the columnar analogue of the Splunk sinks'
-- event_id-based dedup: the delivery path is at-least-once (D5), and because
-- event_id -- and the observed_time / source_type derived from the same
-- observation -- are deterministic, a redelivered event reproduces the identical
-- sorting-key tuple and collapses to a single row on merge rather than
-- duplicating. Queries that must not see a not-yet-merged duplicate use
-- `SELECT ... FINAL` or `GROUP BY event_id`.
--
-- This DDL is applied by the OPERATOR; the sink never creates tables.
--
--   clickhouse-client --database cloudflow < schema/cloudflow_events.sql

CREATE DATABASE IF NOT EXISTS cloudflow;

CREATE TABLE IF NOT EXISTS cloudflow.events
(
    -- ---- common columns (envelope + PacketObservation) --------------------
    event_id           String,                              -- dedup key (D5)
    observed_time      DateTime64(9),                       -- wire observation time
    source_type        LowCardinality(String),              -- dhcpv4 | dhcpv6 | dns
    source_host        LowCardinality(String) DEFAULT '',
    capture_interface  LowCardinality(String) DEFAULT '',
    event_type         LowCardinality(String) DEFAULT '',
    src_ip             String DEFAULT '',
    dst_ip             String DEFAULT '',
    src_mac            String DEFAULT '',

    -- ---- DHCP protocol columns (absent -> default on non-DHCP rows) -------
    message_type       LowCardinality(String) DEFAULT '',   -- DISCOVER/OFFER/.../SOLICIT/...
    client_key         String DEFAULT '',                   -- normalized client id / chaddr / DUID
    requested_address  String DEFAULT '',                   -- DHCPv4 option 50, when present
    assigned_address   String DEFAULT '',                   -- lease / first assigned addr, when present
    is_relayed         UInt8  DEFAULT 0,

    -- ---- DNS protocol columns (absent -> default on non-DNS rows) ---------
    qname              String DEFAULT '',
    qtype              LowCardinality(String) DEFAULT '',    -- A / AAAA / ... (numeric string if unknown)
    qclass             UInt16 DEFAULT 0,
    rcode              LowCardinality(String) DEFAULT '',    -- NOERROR / NXDOMAIN / ...
    rtt_seconds        Float64 DEFAULT 0,
    rtt_valid          UInt8  DEFAULT 0,
    role               LowCardinality(String) DEFAULT '',    -- leg: client_facing / backend / recursion_upstream
    service_role       LowCardinality(String) DEFAULT '',    -- operator tier, when mapped
    client_ip          String DEFAULT '',
    server_ip          String DEFAULT ''
)
ENGINE = ReplacingMergeTree
PARTITION BY toDate(observed_time)
ORDER BY (source_type, observed_time, event_id);
