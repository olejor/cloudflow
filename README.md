# CloudFlow

CloudFlow is a high-performance, packet-derived telemetry pipeline.

It captures traffic using RX ring based collectors, converts observed network behavior into normalized events, streams those events through Redis Streams, and delivers them to sinks such as Splunk.

CloudFlow is built around one principle:

> Trust the wire. Stream the truth.

Application self-reported metrics are not the source of truth in CloudFlow. CloudFlow observes what actually happened on the network and turns those observations into durable, replayable event streams.

## Current status

**v0.1 is implemented and tested**: a DHCPv4/DHCPv6 wire-observed source,
Redis Streams transport, and a C Splunk sink.

```text
RX ring packet capture
  -> DHCPv4/DHCPv6 parsing
  -> CloudFlow protobuf event
  -> Redis Streams
  -> Splunk sink (C)
```

Services:

```text
cloudflow-source-dhcp    (C, implemented)
cloudflow-source-dns     (C, implemented)
cloudflow-sink-splunk    (C, implemented)
```

Redis streams:

```text
cloudflow:v1:wire:dhcpv4   (implemented)
cloudflow:v1:wire:dhcpv6   (implemented)
cloudflow:v1:wire:dns      (v0.2, implemented — see docs/dns-source.md)
```

Redis consumer groups:

```text
sink-splunk
```

The **wire-observed DNS source (v0.2)** captures udp/53 and tcp/53, parses
DNS, and correlates each query to its response into `DnsTransactionEvent`
events on `cloudflow:v1:wire:dns`; the Splunk sink delivers them as
`sourcetype=cloudflow:dns`. See `docs/dns-source.md`.

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
│   ├── cloudflow-redis/
│   ├── cloudflow-packet/
│   └── cloudflow-capture/
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
│   └── cloudflow-sink-splunk/
│       ├── src/
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

## Architecture

Sources are fast, focused, and destination-agnostic: read packets, parse the
protocol, normalize into a CloudFlow event, encode it, push it to Redis
Streams. Sinks read from Redis Streams, decode and validate, transform into
the destination format, deliver, and acknowledge only after confirmed
delivery. See `docs/architecture.md` for the full system overview, the
shared libraries, and the numbered design decisions (`D1`..`D11`); see
`docs/dhcp-source.md` and `docs/dns-source.md` for the two sources in
detail.

## Event model

CloudFlow events represent wire-observed facts, not application claims. The
canonical Redis payload wrapper is `cloudflow.v1.CloudFlowEvent` — an
envelope plus a protocol-specific payload. See `docs/event-model.md` for the
full envelope, event-type vocabulary, and protobuf contract.

## Redis Streams

Redis Streams are the transport and replay buffer between sources and
sinks, read through per-sink consumer groups and acknowledged only after
confirmed delivery. See `docs/redis-streams.md`.

## Splunk sink

`cloudflow-sink-splunk` (C) reads each wire stream through the
`sink-splunk` consumer group, decodes protobuf events, maps them to Splunk
HEC JSON, and delivers them with retry and poison-event isolation. See
`docs/splunk-output.md` for the full pipeline and the canonical HEC mapping,
and `docs/failure-modes.md` for the retry/dead-letter policy.

## Development principles

1. Sources are destination-agnostic.
2. Sinks are independently scalable.
3. Redis consumer groups isolate sink progress.
4. Protobuf schemas are the compatibility contract.
5. Events are observations; metrics are derived later.
6. Backpressure must be visible and deliberate.
7. Event IDs must be stable enough to support duplicate handling.
8. Debug tooling is part of the product, not an afterthought.

## Debug tools

```text
tools/decode-event      decode a CloudFlowEvent from Redis, a file, or stdin, and print JSON
tools/stream-inspect    inspect stream depth, pending entries, consumer groups, and lag
```

See `docs/building-and-testing.md` for details.

## Getting started

### Build dependencies

On Debian/Ubuntu:

```sh
sudo apt-get install -y gcc make pkg-config protobuf-compiler \
    protobuf-c-compiler libprotobuf-c-dev libhiredis-dev libyaml-dev \
    libcurl4-openssl-dev libcunit1-dev redis-server python3 python3-pip
python3 -m pip install protobuf redis requests PyYAML
```

Then:

```sh
make build    # builds every library, source, and sink
make test     # unit tests, sink/source suites, and the integration script
```

See `docs/building-and-testing.md` for the full build/test/CI picture,
`docs/architecture.md` for the system overview and repository layout, and
`docs/dhcp-source.md` for how to run or replay the DHCP source end to end.
