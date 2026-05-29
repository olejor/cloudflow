# cloudflow-sink-splunk

Redis Streams to Splunk HEC sink for CloudFlow events.

Pipeline:

```text
Redis Streams -> protobuf decode -> JSON encode -> Splunk HEC -> XACK
```

Responsibilities:

- consume DHCPv4/DHCPv6 streams using the `sink-splunk` consumer group,
- decode `cloudflow.v1.EventEnvelope`,
- convert events to Splunk-friendly JSON,
- send batches to Splunk HEC,
- acknowledge Redis messages only after confirmed delivery.
