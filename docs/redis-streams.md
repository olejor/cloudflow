# Redis Streams

Redis Streams provide buffering, replay, and consumer group delivery.

Initial streams:

```text
cloudflow:v1:wire:dhcpv4
cloudflow:v1:wire:dhcpv6
```

Entry fields:

```text
schema    cloudflow.v1.EventEnvelope
version   1
encoding  protobuf
payload   <protobuf bytes>
```

Suggested producer command shape:

```text
XADD cloudflow:v1:wire:dhcpv4 MAXLEN ~ 1000000 * schema cloudflow.v1.EventEnvelope version 1 encoding protobuf payload <bytes>
```

Suggested consumer command shape:

```text
XREADGROUP GROUP sink-splunk splunk-01 COUNT 100 BLOCK 1000 STREAMS cloudflow:v1:wire:dhcpv4 >
```

A sink may only acknowledge after confirmed downstream delivery.
