# cloudflow-source-dhcp

DHCPv4/DHCPv6 wire-observed event producer.

Pipeline:

```text
rx-reader -> event-formatter -> redis-producer
```

Responsibilities:

- capture DHCP packets,
- parse DHCPv4 and DHCPv6 messages,
- build `cloudflow.v1.EventEnvelope`,
- encode protobuf,
- write to Redis Streams.

This service must not contain Splunk-specific logic.
