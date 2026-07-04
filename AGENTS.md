# AGENTS.md

This file provides guidance for agents and contributors working in the CloudFlow repository.

## Project identity

CloudFlow is a packet-derived telemetry pipeline.

Its purpose is to create independent, wire-observed telemetry at scale. CloudFlow should not rely on application self-reported metrics as the source of truth. It observes packets, normalizes those observations into events, streams them through Redis Streams, and delivers them to sinks such as Splunk.

Core principle:

> Trust the wire. Stream the truth.

Initial scope:

- DHCPv4 capture and parsing
- DHCPv6 capture and parsing
- protobuf event envelope
- Redis Streams producer
- Splunk sink

Do not broaden the *implementation* beyond what a task asks for. v0.1 (DHCP + Redis + Splunk event sink), the v0.2 wire-observed DNS source, and the Splunk metrics sink are implemented.
The ClickHouse sink is designed in `docs/` but not yet built — implement it only when a task explicitly requests it. A syslog source and a relational sink are not planned. See "Current non-goals" below.

## Architectural rules

### Sources

Source applications produce CloudFlow events.

A source should:

- read packets from the capture path,
- parse only what is needed to produce a valid event,
- normalize the observation into the shared event model,
- encode using protobuf,
- write to Redis Streams,
- remain destination-agnostic.

A source should not:

- know about Splunk-specific formatting,
- contain destination routing logic,
- perform expensive enrichment in the hot packet path,
- use unbounded queues,
- silently drop events without counters/logging.

### Sinks

Sink applications consume CloudFlow events.

A sink should:

- read from Redis Streams using a consumer group,
- decode and validate protobuf events,
- transform events into the destination-specific format,
- deliver events to the destination,
- acknowledge Redis messages only after successful delivery.

A sink should not:

- mutate the canonical event contract,
- acknowledge before confirmed delivery,
- assume it is the only consumer of a stream,
- block other sinks by sharing consumer group state.

### Shared libraries

Shared libraries should contain reusable behavior only:

- event IDs,
- time handling,
- protobuf encoding/decoding,
- Redis producer/consumer wrappers,
- packet parsing helpers,
- metrics/logging helpers,
- retry/backoff logic.

Keep application-specific behavior inside the relevant source or sink.

## Threading model for DHCP source

The DHCP source should follow this model:

```text
rx-reader -> event-formatter -> redis-producer
```

Each stage should communicate through bounded queues.

Expected behavior:

- `rx-reader` reads packets as fast as practical from RX ring or the configured capture mechanism.
- `event-formatter` parses DHCPv4/DHCPv6 packets and builds protobuf events.
- `redis-producer` performs `XADD`, preferably with batching or pipelining when available.

Backpressure must be explicit. If a queue fills, the code must clearly implement one of these policies:

- block,
- drop newest,
- drop oldest,
- sample,
- local spool,
- degraded mode.

Do not add hidden unbounded buffering.

## Event model rules

CloudFlow events are observations. Use `observed` language where appropriate.

Prefer:

```text
dhcpv4.discover.observed
dhcpv6.reply.observed
```

Avoid:

```text
dhcp_metric
dhcp_log
application_latency
```

The shared envelope should include, at minimum:

```text
event_id
schema_version
source_type
source_host
capture_interface
observation_method
observed_time_unix_nano
ingest_time_unix_nano
payload
```

Use nanosecond timestamps when available. Preserve observed packet time separately from ingestion time.

## Protobuf rules

Protobuf is the internal CloudFlow transport format.

Rules:

- Use `proto3`.
- Put schemas under `proto/cloudflow/v1/`.
- Do not reuse field numbers for different meanings.
- Do not rename fields casually once released.
- Reserve removed field numbers and names.
- Keep the envelope stable.
- Add new payload types rather than overloading old ones.

Initial files:

```text
proto/cloudflow/v1/envelope.proto
proto/cloudflow/v1/dhcp.proto
```

Splunk output should normally be JSON generated from decoded protobuf, not raw protobuf blobs.

## Redis Streams rules

Redis Streams are the transport and replay buffer.

Initial streams:

```text
cloudflow:v1:wire:dhcpv4
cloudflow:v1:wire:dhcpv6
```

Consumer groups for the Splunk sinks:

```text
sink-splunk            (event index)
sink-splunk-metrics    (metrics index)
```

Use one consumer group per sink type. Do not make different sinks share a consumer group.

A Redis stream entry should contain enough metadata to decode the payload:

```text
schema    cloudflow.v1.CloudFlowEvent
version   1
encoding  protobuf
payload   <protobuf bytes>
```

A sink may `XACK` only after successful downstream delivery.

## Splunk sink rules

The Splunk sink should:

- consume from `cloudflow:v1:wire:dhcpv4`, `cloudflow:v1:wire:dhcpv6`, and `cloudflow:v1:wire:dns`,
- decode protobuf events,
- convert them to JSON,
- send them to Splunk HEC,
- preserve `event_id`,
- use observed packet time as event time when possible,
- acknowledge Redis messages only after Splunk confirms delivery.

Suggested sourcetypes:

```text
cloudflow:dhcpv4
cloudflow:dhcpv6
cloudflow:dns
```

Malformed events should go to a dead-letter stream or be logged with enough information to debug safely. Do not lose malformed events silently.

## Metrics and observability

CloudFlow may expose metrics about CloudFlow itself. That does not violate the project principle, because these metrics describe the health of the telemetry pipeline, not the application behavior being observed.

Useful CloudFlow service metrics:

```text
packets_received_total
packets_dropped_total
rx_queue_depth
formatter_queue_depth
redis_queue_depth
xadd_latency_seconds
xadd_errors_total
redis_stream_lag
splunk_batch_size
splunk_delivery_latency_seconds
splunk_delivery_errors_total
protobuf_decode_errors_total
```

Do not use application-provided metrics as evidence of application behavior in CloudFlow event modeling.

## Coding guidance

- Prefer simple, explicit code over clever abstractions.
- Keep hot-path allocations low.
- Avoid blocking work in the RX reader.
- Keep parser code heavily tested with fixtures.
- Make failure behavior visible in logs and metrics.
- Use structured logs for CloudFlow services.
- Keep config file examples in `configs/examples/` and service-local examples under each app's `config/` directory.
- Do not commit secrets, Splunk HEC tokens, packet captures with sensitive payloads, or production Redis/Splunk endpoints.

## Test expectations

Add tests for:

- DHCPv4 parsing,
- DHCPv6 parsing,
- protobuf encoding/decoding,
- Redis stream naming and entry format,
- Splunk JSON conversion,
- retry and acknowledgement behavior,
- queue/backpressure behavior.

Packet fixtures should live under:

```text
tests/fixtures/dhcp/
```

Sanitize fixtures before committing.

## Documentation expectations

Update docs when changing architecture, schemas, stream names, or failure behavior.

Important docs:

```text
docs/architecture.md            system overview, design decisions (D1..D11), repo layout
docs/event-model.md              envelope, event types, protobuf contract
docs/redis-streams.md            transport, wire streams, consumer groups, dead-letter
docs/dhcp-source.md              the implemented DHCP source
docs/dns-source.md                the implemented DNS source
docs/splunk-output.md            the Splunk event sink: consumer, HEC mapping, retry policy
docs/splunk-metrics.md           the implemented Splunk metrics sink and its metric mapping
docs/clickhouse-sink.md          the designed (future) ClickHouse analytics sink
docs/failure-modes.md            loss/retry decisions and the tests that prove them
docs/building-and-testing.md    build system, codegen, tests, CI, benchmark, debug tools
```

Docs describe the system in the present tense: what it is, and — for the
ClickHouse sink — what is designed. They are not a changelog; do
not narrate "we did X, then replaced it with Y" in prose. Git history is the
changelog.

Every non-trivial design choice should be documented, especially choices involving data loss, retries, stream trimming, event identity, or schema evolution.

## Current non-goals

Unless a task explicitly requests it, do not implement:

- syslog source,
- MySQL/MariaDB (relational) sink,
- Kubernetes deployment,
- full TCP stream reassembly,
- HTTP parsing,
- application instrumentation agents.

The first deliverable was DHCPv4/DHCPv6 -> Redis Streams -> Splunk (v0.1,
complete). Also implemented:

- a **wire-observed DNS source** (`docs/dns-source.md`) — reuses the shared
  libraries (including `cloudflow-capture`) and adds a stateful query/response
  correlation stage.
- a **Splunk metrics sink** (`docs/splunk-metrics.md`) — a second consumer
  group (`sink-splunk-metrics`) on the same wire streams emitting metric points
  for RTT/rate/count dashboards, built on `libs/cloudflow-sink-core`.

Explicitly requested and designed (not yet implemented):

- a **ClickHouse sink** (`docs/clickhouse-sink.md`) — columnar analytics over
  the raw firehose, sequenced after the DNS source.

A relational sink for derived state (a lease table, a client inventory) is
deliberately **not** planned yet — it needs a correlation/aggregation stage
first. The repository can remain extensible for the remaining items above.
