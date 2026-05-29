# CloudFlow

CloudFlow is a high-performance, packet-derived telemetry pipeline.

It captures traffic using RX ring based collectors, converts observed network behavior into normalized events, streams those events through Redis Streams, and delivers them to sinks such as Splunk.

CloudFlow is built around one principle:

> Trust the wire. Stream the truth.

The first implementation scope is deliberately small:

- DHCPv4 packet capture and event generation
- DHCPv6 packet capture and event generation
- Protobuf event encoding
- Redis Streams transport using `XADD`
- Splunk delivery through a dedicated sink

Application self-reported metrics are not the source of truth in CloudFlow. CloudFlow observes what actually happened on the network and turns those observations into durable, replayable event streams.

## Current scope

```text
RX ring packet capture
  -> DHCPv4/DHCPv6 parsing
  -> CloudFlow protobuf event
  -> Redis Streams
  -> Splunk sink
```

Initial services:

```text
cloudflow-source-dhcp
cloudflow-sink-splunk
```

Initial Redis streams:

```text
cloudflow:v1:wire:dhcpv4
cloudflow:v1:wire:dhcpv6
```

Initial Redis consumer groups:

```text
sink-splunk
```

## Repository layout

```text
cloudflow/
├── README.md
├── AGENTS.md
├── docs/
│   ├── architecture.md
│   ├── event-model.md
│   ├── redis-streams.md
│   ├── splunk-output.md
│   └── failure-modes.md
│
├── proto/
│   └── cloudflow/
│       └── v1/
│           ├── common.proto
│           ├── envelope.proto
│           └── dhcp.proto
│
├── libs/
│   ├── cloudflow-core/
│   ├── cloudflow-codec/
│   ├── cloudflow-redis/
│   └── cloudflow-packet/
│
├── sources/
│   └── cloudflow-source-dhcp/
│       ├── src/
│       ├── config/
│       ├── systemd/
│       └── README.md
│
├── sinks/
│   └── cloudflow-sink-splunk/
│       ├── src/
│       ├── config/
│       ├── systemd/
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
│   └── performance/
│
├── scripts/
└── .github/
    └── workflows/
```

## Architecture

CloudFlow sources should be fast, focused, and destination-agnostic.

A source app should only:

1. read packets from the capture path,
2. parse the protocol,
3. normalize the observation into a CloudFlow event,
4. encode the event,
5. push the event to Redis Streams.

A sink app should only:

1. read CloudFlow events from Redis Streams,
2. decode and validate them,
3. transform them into the destination format,
4. deliver them,
5. acknowledge the Redis message only after confirmed delivery.

### DHCP source thread model

```text
rx-reader -> event-formatter -> redis-producer
```

The queues between these stages must be bounded. If backpressure appears, the process must make an explicit choice: drop, block, sample, or enter degraded mode. Silent unbounded memory growth is not acceptable.

## Event model

CloudFlow events represent wire-observed facts, not application claims.

The canonical Redis payload wrapper is `cloudflow.v1.CloudFlowEvent`.

Minimum event envelope fields:

```text
event_id
schema_version
source_type
source_host
capture_interface
observation_method
observed_time_unix_nano
ingest_time_unix_nano
event_type
visibility
confidence
payload_schema
payload
```

For DHCP, the payload should distinguish DHCPv4 and DHCPv6 while preserving both the packet-level wire observation and a decoded operational view where possible.

Example event classes:

```text
dhcpv4.packet.observed
dhcpv4.discover.observed
dhcpv4.offer.observed
dhcpv4.request.observed
dhcpv4.ack.observed
dhcpv4.nak.observed
dhcpv4.lease.derived
dhcpv6.packet.observed
dhcpv6.solicit.observed
dhcpv6.advertise.observed
dhcpv6.request.observed
dhcpv6.reply.observed
```

## Redis Streams

Redis Streams are the transport and replay buffer between sources and sinks.

Suggested stream names:

```text
cloudflow:v1:wire:dhcpv4
cloudflow:v1:wire:dhcpv6
```

Suggested fields:

```text
schema      cloudflow.v1.CloudFlowEvent
version     1
encoding    protobuf
payload     <protobuf bytes>
```

Suggested producer behavior:

```text
XADD cloudflow:v1:wire:dhcpv4 MAXLEN ~ <limit> * schema cloudflow.v1.CloudFlowEvent version 1 encoding protobuf payload <bytes>
```

Suggested consumer behavior:

```text
XREADGROUP GROUP sink-splunk <consumer-name> STREAMS cloudflow:v1:wire:dhcpv4 >
```

Only acknowledge after successful downstream delivery:

```text
XACK cloudflow:v1:wire:dhcpv4 sink-splunk <message-id>
```

## Splunk sink

The Splunk sink should read from Redis using its own consumer group.

```text
Redis Stream -> protobuf decode -> Splunk JSON event -> Splunk HEC -> XACK
```

Splunk output should be searchable and readable. Do not insert opaque protobuf blobs directly into Splunk unless a deliberate Splunk-side decoder exists.

Recommended Splunk behavior:

- decode protobuf into JSON
- preserve `event_id`
- preserve `observed_time_unix_nano`
- use the observed event time as Splunk event time where practical
- map DHCPv4 and DHCPv6 into clear sourcetypes
- acknowledge Redis messages only after Splunk confirms receipt

Example sourcetypes:

```text
cloudflow:dhcpv4
cloudflow:dhcpv6
```

## Failure policy

CloudFlow should make failure behavior explicit.

Important questions:

```text
If Redis is unavailable, do sources block, drop, or local-spool?
If Splunk is unavailable, how long does the sink retry?
If Redis streams grow too large, what retention policy applies?
If internal queues fill, what is dropped first?
If protobuf decode fails, is the event dead-lettered or discarded?
```

Initial recommendation:

- DHCP source should use bounded queues.
- Redis producer should expose queue depth, XADD latency, and XADD failures.
- Splunk sink should retry transient failures.
- Splunk sink should support a dead-letter stream for malformed events.
- All services should expose operational metrics about CloudFlow itself, while keeping application behavior metrics derived from packet observations.

## Development principles

1. Sources are destination-agnostic.
2. Sinks are independently scalable.
3. Redis consumer groups isolate sink progress.
4. Protobuf schemas are the compatibility contract.
5. Events are observations; metrics are derived later.
6. Backpressure must be visible and deliberate.
7. Event IDs must be stable enough to support duplicate handling.
8. Debug tooling is part of the product, not an afterthought.

## Planned tools

```text
tools/decode-event
```

Decode a protobuf payload from Redis and print JSON.

```text
tools/stream-inspect
```

Inspect stream depth, pending entries, consumer groups, and recent events.

## Getting started

This repository is currently a skeleton. A first implementation should add:

1. protobuf generation tooling,
2. DHCPv4/DHCPv6 parser tests,
3. Redis producer library,
4. Splunk HEC client,
5. local integration environment with Redis,
6. sample packet fixtures.

Recommended first milestone:

```text
Capture one DHCPv4 packet
  -> parse message type and client MAC
  -> encode CloudFlowEvent protobuf
  -> XADD to Redis
  -> read with Splunk sink
  -> emit JSON to stdout
```

Then replace stdout with Splunk HEC delivery.
