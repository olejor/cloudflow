# Failure modes

CloudFlow must make data-loss and retry decisions explicit.

## Redis unavailable

Choose and document one policy before production use:

- block producer
- drop with counters
- local spool
- degraded sampling

## Splunk unavailable

Initial recommendation:

- keep messages pending in Redis consumer group,
- retry with backoff,
- do not acknowledge until delivery succeeds,
- alert on growing pending count and consumer lag.

## Queue pressure

All internal queues must be bounded. Queue pressure must be visible through logs and metrics.

## Malformed events

Malformed protobuf or invalid event payloads should be routed to a dead-letter stream when possible.
