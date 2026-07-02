# Architecture

CloudFlow starts with DHCPv4/DHCPv6 packet observations and ends with searchable Splunk events.

```text
rx-reader -> event-formatter -> redis-producer -> Redis Streams -> cloudflow-sink-splunk -> Splunk HEC
```

The source side must stay fast and destination-agnostic. The sink side owns destination-specific transformation and delivery semantics.

The detailed component design and work-package breakdown for v0.1 is in `docs/design/` (start with `00-overview.md`).

## Source pipeline

- `rx-reader`: captures packets from the configured interface/capture mechanism.
- `event-formatter`: parses DHCPv4/DHCPv6 packets and builds `cloudflow.v1.EventEnvelope`.
- `redis-producer`: writes encoded protobuf events to Redis Streams.

All inter-stage queues must be bounded.

## Sink pipeline

- `redis-consumer`: reads from Redis Streams using the `sink-splunk` consumer group.
- `protobuf-decoder`: decodes and validates CloudFlow events.
- `splunk-encoder`: converts events to Splunk-friendly JSON.
- `hec-client`: sends events to Splunk HEC.
- `ack-manager`: acknowledges Redis messages only after delivery succeeds.
