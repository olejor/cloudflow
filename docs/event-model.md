# Event model

CloudFlow events are wire-observed facts.

The canonical event wrapper is `cloudflow.v1.CloudFlowEvent`.

Required concepts:

- stable event ID
- schema version
- source type
- source host
- capture interface
- observation method
- observed timestamp
- ingest timestamp
- event type
- protocol-specific payload

Initial event types:

```text
dhcpv4.discover.observed
dhcpv4.offer.observed
dhcpv4.request.observed
dhcpv4.decline.observed
dhcpv4.ack.observed
dhcpv4.nak.observed
dhcpv4.release.observed
dhcpv4.inform.observed
dhcpv6.solicit.observed
dhcpv6.advertise.observed
dhcpv6.request.observed
dhcpv6.confirm.observed
dhcpv6.renew.observed
dhcpv6.rebind.observed
dhcpv6.reply.observed
dhcpv6.release.observed
dhcpv6.decline.observed
dhcpv6.relay-forw.observed
dhcpv6.relay-repl.observed
```
