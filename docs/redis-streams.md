# Redis Streams

Redis Streams are the transport between sources and sinks: they provide
buffering, durable replay, and consumer-group delivery. A source only ever
appends (`XADD`); a sink reads through a named consumer group and acknowledges
after confirmed delivery.

Wire streams:

```text
cloudflow:v1:wire:dhcpv4   (v0.1, implemented)
cloudflow:v1:wire:dhcpv6   (v0.1, implemented)
cloudflow:v1:wire:dns      (v0.2, designed — see docs/dns-source.md)
```

Entry fields (the payload wrapper is `cloudflow.v1.CloudFlowEvent`, which
contains the `EventEnvelope` plus the protocol payload — see
`proto/cloudflow/v1/envelope.proto`):

```text
schema    cloudflow.v1.CloudFlowEvent
version   1
encoding  protobuf
payload   <protobuf bytes>
```

Suggested producer command shape:

```text
XADD cloudflow:v1:wire:dhcpv4 MAXLEN ~ 1000000 * schema cloudflow.v1.CloudFlowEvent version 1 encoding protobuf payload <bytes>
```

Suggested consumer command shape:

```text
XREADGROUP GROUP sink-splunk splunk-01 COUNT 100 BLOCK 1000 STREAMS cloudflow:v1:wire:dhcpv4 >
```

A sink may only acknowledge after confirmed downstream delivery.

## Dead-letter stream

Events the Splunk sink cannot process (protobuf decode failure, HEC 4xx
rejection) are written to a dead-letter stream before the original entry is
acknowledged:

```text
cloudflow:v1:deadletter:sink-splunk    (XADD MAXLEN ~ 100000)
```

Entry fields:

```text
reason         decode_error | hec_rejected
origin_stream  <stream name>
origin_id      <redis entry id>
error          <short message>
payload        <original payload bytes, verbatim>
```

## Consumer groups

Each stream is trimmed with `MAXLEN ~` (approximate trimming; the trim target
comes from `redis.maxlen_approx` in the source's config, and from
`configs/examples/redis.yaml`), so Redis itself never grows unbounded.

Every sink type reads through its own consumer group, so one sink's progress
and pending entries never block another sink reading the same stream:

```text
sink-splunk    (cloudflow-sink-splunk's group, on every wire stream it consumes)
```

Details of consumer behavior (`XAUTOCLAIM`, `XREADGROUP`, ack-after-delivery)
live in `docs/splunk-output.md`.
