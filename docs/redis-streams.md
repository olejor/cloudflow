# Redis Streams

Redis Streams provide buffering, replay, and consumer group delivery.

Initial streams:

```text
cloudflow:v1:wire:dhcpv4
cloudflow:v1:wire:dhcpv6
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
