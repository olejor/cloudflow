# Architecture

CloudFlow turns wire-observed packets into searchable Splunk events. The
first source is DHCP; a wire-observed DNS source ships in v0.2.

```text
sources -> Redis Streams -> cloudflow-sink-splunk -> Splunk HEC
```

Sources are fast and destination-agnostic; the sink owns destination-specific
transformation and delivery semantics. Everything between a source and the
sink is the canonical `cloudflow.v1.CloudFlowEvent` (an `EventEnvelope` plus a
protocol-specific payload), encoded as protobuf and carried on Redis Streams.

The other topic docs go deeper on each area: `docs/event-model.md` (envelope
and payload contract), `docs/redis-streams.md` (transport), `docs/dhcp-source.md`
(the DHCP source), `docs/dns-source.md` (the DNS source),
`docs/splunk-output.md` (the sink), `docs/failure-modes.md` (loss/retry
policy), and `docs/building-and-testing.md` (build, tests, CI). What is
implemented today versus designed is called out below.

## Shared libraries

Every source and the sink are built from five small libraries under `libs/`:

- **`cloudflow-core`** — time helpers, structured logging, the stop-flag
  shutdown mechanism, deterministic event IDs, atomic stats-counter macros,
  and the bounded SPSC `cf_queue_t` used between pipeline stages.
- **`cloudflow-codec`** — the generated `protobuf-c` bindings for
  `proto/cloudflow/v1/*.proto`, committed so builds never require `protoc`.
- **`cloudflow-packet`** — protocol-agnostic Ethernet/VLAN/IPv4/IPv6/UDP
  decapsulation, plus the DHCPv4 and DHCPv6 parsers.
- **`cloudflow-capture`** — the shared capture layer used by both the DHCP
  and DNS sources: the TPACKET_V3 rx-ring reader, pcap replay, the queue
  backpressure policy, and the cBPF filter assembler.
- **`cloudflow-redis`** — the `hiredis`-based pipelined `XADD` producer used
  by every source to write to Redis Streams.

## Sources

### DHCP source (v0.1, implemented) — `cloudflow-source-dhcp`

```text
rx-reader -> event-formatter -> redis-producer
```

- `rx-reader`: captures packets from the configured interface (TPACKET_V3
  ring) or a pcap replay, filtered in-kernel to DHCP.
- `event-formatter`: parses DHCPv4/DHCPv6, builds a
  `cloudflow.v1.CloudFlowEvent` (envelope + `DhcpV4PacketEvent` /
  `DhcpV6PacketEvent` payload), and encodes it with protobuf.
- `redis-producer`: writes encoded events to Redis Streams
  (`cloudflow:v1:wire:dhcpv4`, `cloudflow:v1:wire:dhcpv6`).

The formatter is stateless: one packet in, one event out.

### DNS source (v0.2, implemented) — `cloudflow-source-dns`

```text
rx-reader -> parse + correlate -> redis-producer
```

DNS is the same spine, plus a stateful **correlation stage**: it captures
udp/53 and tcp/53 and matches queries to responses in a bounded pending-query
table to produce `dns.transaction.observed` events carrying per-leg RTT and a
leg role (client-facing / backend / recursion-upstream), alongside
`dns.query.unanswered` and `dns.response.unmatched` for the legs that do not
correlate. It writes to `cloudflow:v1:wire:dns`. This is the one deliberate
departure from the stateless-source model; it is bounded and loss-accounted
like every queue.

## Transport

All inter-stage queues are bounded SPSC queues; backpressure is an explicit,
counted policy (see `failure-modes.md`). Redis Streams are the transport and
the durable replay buffer between sources and the sink (see
`redis-streams.md`).

## Sink pipeline (v0.1, implemented) — `cloudflow-sink-splunk` (C)

```text
Redis Stream -> protobuf decode -> Splunk HEC JSON -> HEC POST -> XACK
```

- `redis-consumer`: reads with the `sink-splunk` consumer group, reclaiming
  stale pending entries (`XAUTOCLAIM`).
- `protobuf-decoder`: validates the entry `schema`/`encoding` fields and
  unpacks the `CloudFlowEvent`.
- `splunk-encoder`: converts the event to HEC JSON (see `docs/splunk-output.md`).
- `hec-client`: POSTs to Splunk HEC with retry and poison-batch isolation.
- `ack-manager`: acknowledges Redis entries only after confirmed delivery, or
  after an unprocessable entry is dead-lettered.

The sink is C11, the same language as the source and shared libraries; its
JSON mapping is a stable contract also used by the `decode-event` debug tool.
See `docs/dhcp-source.md` for the DHCP source in detail and
`docs/splunk-output.md` for the sink in detail.

## Sinks

Sinks are destination-agnostic consumers of the wire streams, and Redis
consumer groups isolate their progress — so **any number of sinks can read the
same streams independently**, each transforming the same `CloudFlowEvent`s for
a different destination. They all share one spine (the consumer /
`XAUTOCLAIM` / ack-after-delivery / retry / dead-letter machinery); only the
transform and delivery client differ.

| Sink | Destination | Purpose | Status |
|---|---|---|---|
| `cloudflow-sink-splunk` | Splunk HEC event index | full-fidelity forensic record; searchable JSON | v0.1, implemented |
| `cloudflow-sink-splunk-metrics` | Splunk HEC metrics index | rates, latency distributions, counts for dashboards/alerting | implemented — `docs/splunk-metrics.md` |
| `cloudflow-sink-clickhouse` | ClickHouse | columnar/analytical navigation of the raw firehose | implemented — `docs/clickhouse-sink.md` |

All three sinks are implemented; each is a distinct consumer group on the same
wire streams. The ClickHouse sink writes each event as one row into a wide
`ReplacingMergeTree` `events` table (`event_id` dedup, D5) for fast columnar
scans, joins and high-cardinality group-bys.

## Design decisions

Numbered so other docs, PRs, and code comments can reference them (`D1`..`D11`).

- **D1 — Languages.** The DHCP source, the shared libraries, and the Splunk
  sink are C11. Debug tools (`decode-event`, `stream-inspect`) are Python —
  they are interactive utilities outside the data path.
- **D2 — Protobuf runtime.** `protobuf-c` for the C services. Generated code
  is committed under `libs/cloudflow-codec/gen/`, so builds never require
  `protoc` (see `docs/building-and-testing.md`).
- **D3 — Redis client.** A **standalone** Redis using `hiredis` with
  pipelined `XADD`. A Redis Stream is a single key, so standalone keeps the
  local dev loop trivial (`make local-redis`). The config keeps a list of
  endpoints and uses the first, failing over to the next on connect failure.
- **D4 — Thread model.** Exactly three threads in each source, joined by two
  bounded SPSC `cf_queue` queues:
  `rx-reader -> [cf_packet_item_t] -> event-formatter -> [cf_event_item_t] -> redis-producer`.
- **D5 — Event identity.** `event_id` is deterministic: the lowercase-hex,
  128-bit truncation of SHA-256 over
  `(source_host, capture_interface, observed_time_unix_nano, raw frame bytes)`.
  Replaying the same capture yields the same IDs, which is what makes
  downstream duplicate handling possible.
- **D6 — Configuration.** YAML files (the examples in `configs/examples/` are
  the schema), loaded with `libyaml`, with environment-variable overrides for
  endpoints and secrets. Secrets (the Splunk HEC token) are env-only, never in
  YAML.
- **D7 — Capture.** `AF_PACKET` + `PACKET_RX_RING` with **TPACKET_V3** block
  ring and epoll. A fixed, VLAN-aware cBPF program filters UDP ports
  67/68/546/547 in-kernel. The `capture.filter` string in the config is
  informational only, logged with a warning if it differs from the builtin.
- **D8 — Metrics.** Atomic counters, reported as one structured JSON log line
  per stats interval, using the metric names in `AGENTS.md`. No Prometheus
  endpoint.
- **D9 — Backpressure.** Every queue has an explicit `on_full` policy from
  config: `drop_newest` (default), `drop_oldest`, or `block`. Every drop
  increments a counter that appears in the stats line. No hidden buffering.
- **D10 — Parse placement.** The rx-reader does no parsing: it copies the
  frame plus ring timestamp into the packet queue and returns the block to
  the kernel. All DHCP parsing and protobuf building happens in the
  event-formatter thread, which may allocate; the rx thread does not allocate
  in steady state.
- **D11 — Event size.** `CLOUDFLOW_EVENT_MAX_SIZE` is 8192 bytes: a fully
  populated `DhcpV4PacketEvent` carries the raw payload plus every option
  value twice (raw + decoded) and can exceed 4096. If an encoded event still
  exceeds the cap, the formatter drops `raw_dhcp_payload`, sets
  `raw_payload_truncated = true`, and re-encodes; if it still does not fit,
  the event is dropped with a counter.

## Repository layout

```text
cloudflow/
├── README.md
├── AGENTS.md
├── docs/
│   ├── architecture.md
│   ├── event-model.md
│   ├── redis-streams.md
│   ├── dhcp-source.md
│   ├── dns-source.md
│   ├── splunk-output.md
│   ├── failure-modes.md
│   └── building-and-testing.md
│
├── proto/
│   └── cloudflow/
│       └── v1/
│           ├── common.proto
│           ├── envelope.proto
│           ├── dhcp.proto
│           └── dns.proto
│
├── libs/
│   ├── cloudflow-core/
│   ├── cloudflow-codec/
│   ├── cloudflow-packet/
│   ├── cloudflow-capture/
│   └── cloudflow-redis/
│
├── sources/
│   ├── cloudflow-source-dhcp/
│   │   ├── src/
│   │   ├── tests/
│   │   ├── systemd/
│   │   └── README.md
│   └── cloudflow-source-dns/
│       ├── src/
│       ├── tests/
│       ├── systemd/
│       └── README.md
│
├── sinks/
│   ├── cloudflow-sink-splunk/
│   │   ├── src/
│   │   ├── config/
│   │   ├── systemd/
│   │   ├── tests/
│   │   └── README.md
│   ├── cloudflow-sink-splunk-metrics/
│   │   ├── src/
│   │   ├── config/
│   │   ├── systemd/
│   │   ├── tests/
│   │   └── README.md
│   └── cloudflow-sink-clickhouse/
│       ├── src/
│       ├── schema/
│       ├── config/
│       ├── systemd/
│       ├── tests/
│       └── README.md
│
├── tools/
│   ├── decode-event/
│   └── stream-inspect/
│
├── configs/
│   └── examples/
│       ├── dhcp-source.yaml
│       ├── redis.yaml
│       └── splunk-sink.yaml
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── fixtures/
│   ├── fuzz/
│   └── performance/
│
├── scripts/
└── .github/
    └── workflows/
```
