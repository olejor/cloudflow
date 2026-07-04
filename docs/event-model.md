# Event model

CloudFlow events are wire-observed facts. The canonical event wrapper is
`cloudflow.v1.CloudFlowEvent` — an `EventEnvelope` plus a protocol-specific
payload (`proto/cloudflow/v1/envelope.proto`).

## Envelope fields

The shared `EventEnvelope` carries, for every event:

```text
event_id                 stable, deterministic per observation (see below)
schema_version
source_type              "dhcpv4" | "dhcpv6" | "dns"
source_host
source_instance
capture_interface
observation_method       "rxring" | "pcap-replay" | (future) "dnsdist-protobuf"
observed_time_unix_nano  from the capture path
ingest_time_unix_nano    when CloudFlow built the event
event_type               e.g. "dhcpv4.ack.observed"
visibility               VisibilityLevel (usually VISIBILITY_PACKET_PAYLOAD)
confidence               ObservationConfidence (OBSERVED / DERIVED / INFERRED)
payload_schema           fully-qualified payload message name
stream_name              the Redis stream the event was written to
```

`event_id` is a deterministic hash of the observation (D5 in
`docs/architecture.md`), so replay and redelivery reproduce the same id
rather than minting a new one — downstream duplicate suppression keys on it.

## DHCP event types (v0.1, implemented)

```text
dhcpv4.packet.observed        (fallback: no/unknown message type)
dhcpv4.discover.observed
dhcpv4.offer.observed
dhcpv4.request.observed
dhcpv4.decline.observed
dhcpv4.ack.observed
dhcpv4.nak.observed
dhcpv4.release.observed
dhcpv4.inform.observed
dhcpv4.lease.derived          (reserved for a future correlation stage)
dhcpv6.packet.observed        (fallback)
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

DHCP payloads are `DhcpV4PacketEvent` / `DhcpV6PacketEvent`
(`proto/cloudflow/v1/dhcp.proto`): each preserves the raw wire observation, a
best-effort decoded option view, and CloudFlow's derived interpretation.

## DNS event types (v0.2, designed — `docs/dns-source.md`)

The DNS source is transaction-oriented: it correlates a query with its
response rather than emitting a raw event per packet.

```text
dns.transaction.observed      query matched to its response; carries rtt_nanos + leg role
dns.query.unanswered          query evicted from the pending table on timeout
dns.response.unmatched        response with no pending query (capture gap / spoofing signal)
```

DNS payload is `DnsTransactionEvent` (`proto/cloudflow/v1/dns.proto`, not yet
added — see `docs/dns-source.md`): both packet observations when present, the
decoded query and response messages, the leg `role`
(client-facing / backend / recursion-upstream), and per-leg RTT.

## Observed identity — "who did this?"

Every event answers "who was the source" but *where* the useful answer lives
differs by protocol, so it is worth stating explicitly. Every payload carries
a `PacketObservation` (`common.proto`) with the raw wire source —
`link.src_mac`, `network.src_ip` / `dst_ip`, `transport.src_port` /
`dst_port` — so the L2/L3/L4 source is always present. On top of that:

- **DHCP.** The L3 source is usually `0.0.0.0`: a client sending DISCOVER /
  REQUEST has no lease yet, so `network.src_ip` is not the identity. The
  meaningful client identity is derived into
  `DhcpV4PacketEvent.interpretation.normalized_client_key` (the client-id from
  option 61, else the `chaddr` MAC), with `header.chaddr_mac` and — for
  relayed traffic — the relay `giaddr` and option 82 circuit/remote-id
  alongside it. So for DHCP, "who asked" is the client MAC / client-id plus
  relay context, not `src_ip`.
- **DNS** (designed). The L3 source *is* the identity: `query_packet`'s
  `network.src_ip` is the client on the client-facing leg, or the recursor on
  the upstream leg. Combined with the transaction's `role`, that distinguishes
  "a client queried us" from "we queried upstream". `DnsTransactionEvent`
  surfaces `client_ip` / `client_port` / `server_ip` directly (see
  `docs/dns-source.md`) so downstream sinks do not have to reach into the
  nested packet observation to dimension by client.

Sinks rely on this: the Splunk event sink keeps identity searchable at its
`event.<payload>.…` path, and the metrics sink (`docs/splunk-metrics.md`) uses
the normalized identity — client key / client IP / role — as metric
dimensions. Because identity is a first-class, per-protocol concept rather than
"whatever `src_ip` happens to be", a sink can dimension DHCP by client MAC and
DNS by client IP without special-casing empty addresses.

## Protobuf contract

The schema under `proto/cloudflow/v1/` is the compatibility contract between
every source and the sink, so it follows a small set of rules:

- **proto3**, one package per version (`cloudflow.v1`).
- Field numbers are **append-only**: never reused for a different meaning,
  never renumbered once released.
- Removing a field reserves both its number and its name
  (`reserved 7; reserved "old_field";`) rather than deleting the entry
  outright, so old numbers can never be accidentally recycled.
- Field names are not renamed casually once released — a rename is a schema
  change like any other and needs the same care as adding a field.
- A new kind of observation gets a **new payload message and a new
  `CloudFlowEvent.payload` oneof field** (e.g. `dns_transaction = 23`) rather
  than overloading an existing payload message with unrelated fields.
- The envelope (`EventEnvelope`, `common.proto`) stays stable across payload
  types — every event, regardless of protocol, carries the same envelope
  fields listed above.
- Generated code (`protobuf-c` under `libs/cloudflow-codec/gen/`) is
  committed; see `docs/building-and-testing.md` for the codegen pipeline and
  its drift check.
