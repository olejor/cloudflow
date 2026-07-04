# CloudFlow DNS source design (v0.2)

This is the design and reference for the second CloudFlow source:
wire-observed DNS telemetry. It follows the same shape as the DHCP source
(`docs/dhcp-source.md`) and reuses everything protocol-agnostic — the core
library, the codec, the packet decap library, the shared `cloudflow-capture`
library, the Redis producer, and the Splunk sink. Read `docs/architecture.md`
first for the project conventions and decision numbering (`D1`..`D11`); this
document adds DNS-specific decisions (prefixed `DNS-Dn`) and the work-package
roadmap (`WP-DNSnn`) it was built along.

> **Scope note.** The DNS source is the v0.2 deliverable, built as an explicit
> follow-on to v0.1. It does not change the v0.1 deliverable; it defines v0.2.

## Why wire capture (and why dstore stays)

You run pdns-recursor and pdns-authoritative, each behind dnsdist, and dnsdist
has a protobuf logging feed (dstore). The CloudFlow DNS source captures the
wire — udp/53 and tcp/53, no DoH/DoT — rather than consuming dstore, because
the value CloudFlow adds is telemetry that does not depend on dnsdist being
healthy or in-path: it observes what actually arrived at and left the host,
including traffic that bypasses dnsdist, spoofed floods, and malformed packets
dnsdist rejected silently. Since DoH/DoT are out of scope, the wire view of
your DNS is complete.

dstore remains the right source for two things the wire cannot give (see
"Non-goals" below): stitching a client query to the upstream fan-out it
triggered, and cache-hit accounting. The event model is designed so a future
dstore bridge can feed the *same* streams and sinks with
`observation_method = "dnsdist-protobuf"` and
`visibility = VISIBILITY_ENDPOINT_OBSERVED`, cleanly labeled alongside the
wire feed. That bridge is not part of this design.

## Decisions

Numbered `DNS-D1…`, continuing the spirit of `docs/architecture.md`'s
`D1…D11`. Deviations must be flagged in the PR and this doc updated.

- **DNS-D1 — Transport scope.** udp/53 and tcp/53 only. No DoH, DoT, DoQ.
  DNS-over-TCP is parsed only when a full DNS message (its 2-byte length
  prefix plus the message) fits within a single captured segment; multi-
  segment TCP messages (large responses, AXFR/IXFR) are counted and emitted
  as `dns.message.partial` with no decoded body, never reassembled (full TCP
  reassembly is a standing non-goal in `AGENTS.md`). AXFR/IXFR is a case
  where dstore or the auth server's own logs are the honest source.
- **DNS-D2 — Reuse the v0.1 spine.** The DNS source is a new app under
  `sources/cloudflow-source-dns/` built from the existing libraries:
  `cloudflow-core` (queues, time, log, sync, event-id, stats),
  `cloudflow-codec` (protobuf-c), `cloudflow-packet` (`cf_decap_udp` for UDP;
  a new `cf_decap_tcp` helper for the TCP case — see WP-DNS02),
  `cloudflow-redis` (the XADD producer, unchanged). The Splunk sink
  (`cloudflow-sink-splunk`, C) consumes the new stream with no code change
  beyond a sourcetype mapping and the generic transform already handling any
  `CloudFlowEvent`.
- **DNS-D3 — Stream and event identity.** New stream
  `cloudflow:v1:wire:dns` (`CF_STREAM_DNS` and `CF_PROTO_DNS` already exist in
  `libs/cloudflow-core/cloudflow.h`). `event_id` uses the existing
  deterministic scheme (D5) but over the **transaction**, not a single
  packet: hashed from `(source_host, capture_interface,
  query_observed_time_unix_nano, query_frame_bytes)` so replay is stable and
  a transaction has one stable id. Unanswered/unmatched events hash the one
  packet they have.
- **DNS-D4 — Transaction-only event model (default).** The source emits
  correlated transactions, not raw per-packet query/response events. Three
  event types cover every outcome so nothing is hidden:
  - `dns.transaction.observed` — a query matched to its response, carrying
    both, plus `rtt_nanos` and the leg `role`.
  - `dns.query.unanswered` — a query evicted from the pending table on
    timeout (loss, drop, or a real gap).
  - `dns.response.unmatched` — a response with no pending query (capture gap,
    or a spoofing/poisoning signal worth surfacing).
  A config knob `emit_raw_query_events` (default false) may later add an
  immediate `dns.query.observed` for security/liveness; it is specified but
  not implemented in v0.2 to keep event volume down.
- **DNS-D5 — Correlation lives in the source.** RTT needs capture-time
  correlation, so the source gains a stateful **correlation stage** between
  parse and encode: a bounded pending-query table keyed by the DNS-D6 tuple,
  matching responses and computing RTT. This is the one deliberate departure
  from the DHCP source's stateless-observer model. It is bounded exactly like
  the queues (DNS-D8): fixed capacity, timeout eviction, and every
  eviction/overflow increments a named counter. Correlating downstream in
  Splunk is explicitly rejected — it is lossy at query volume and destroys
  sub-millisecond timestamp fidelity.
- **DNS-D6 — Correlation key.** A transaction is keyed by
  `(transport, local_is_server, client_ip, client_port, server_ip, server_port,
  dns_id, qname_canonical, qtype, qclass)`. Query and response are the same
  key with endpoints swapped; `qname_canonical` is the lowercased,
  0x20-normalized name (so DNS-0x20 case randomization does not break
  matching). The pending table is keyed on the query's view; a response is
  looked up by swapping endpoints.
- **DNS-D7 — Leg classification.** Every transaction carries
  `role ∈ {CLIENT_FACING, BACKEND, RECURSION_UPSTREAM, UNKNOWN}`, decided by
  *which side owns port 53*, in this priority:
  1. **Local-IP-set membership (authoritative).** The set of local service
     addresses is auto-derived from the capture interface at startup and
     extended by config (`dns.local_service_addresses`). Works on SPAN/mirror
     captures where kernel packet direction is meaningless.
  2. **Capture direction (cross-check only).** `CaptureDirection` from the
     ring, used to confirm/tie-break, never as the sole signal.
  Rules: local side owns `:53` → `CLIENT_FACING`; remote `:53` is in the
  configured backend set (`dns.backend_addresses`) → `BACKEND`; remote `:53`
  otherwise → `RECURSION_UPSTREAM`; indeterminate → `UNKNOWN` (counted).
  Source/destination port alone cannot distinguish client from upstream —
  both are `ephemeral → :53` — which is why the local/backend address sets
  (DNS-D2's "auto + config override") are required, and the backend set in
  particular is the only thing separating a dnsdist→pdns query from an
  internet-upstream query.

  **DNS-D7 extension — per-transaction service role (WP-DNS11a).** Beyond the
  leg `role`, each transaction also carries a config-driven `service_role`: an
  arbitrary operator label (e.g. `dnsdist` / `recursor` / `authoritative`).
  The wire cannot tell a recursor from an authoritative — both listen on `:53`
  — so the label is not inferred; it is looked up from config, keyed on the
  transaction's **server-side address** (the endpoint that owns `:53`, which
  the classifier above already identifies). Config (`dns.service_roles`) maps
  each of the operator's DNS service IPs to a label; a transaction's
  `service_role` is the label for its `server_ip`, or empty when that address
  is unmapped or the server side is indeterminate. Because it keys on the
  server IP, both a client→recursor and a dnsdist→recursor transaction resolve
  to the same label. It is an additional operator dimension and does **not**
  change the leg `role`; the Splunk event sink now routes the sourcetype by it
  (`cloudflow:dns:<service_role>`, WP-DNS11b — see docs/splunk-output.md).
- **DNS-D8 — Bounded everything, visible loss.** The DNS source adds the
  correlation table to the existing bounded queues. Volume is far higher than
  DHCP, so the source ships first-class sampling/emit policy
  (`dns.emit_policy`): `all` (default for now), or predicate-based (e.g.
  always emit non-NOERROR rcodes, unusual qtypes, unmatched/unanswered;
  sample routine A/AAAA NOERROR at a configured rate). Every drop — queue
  full, table full, table eviction, sampled-out — is a named counter in the
  stats line. No silent loss.
- **DNS-D9 — Timestamps.** `rtt_nanos = response.observed_time_unix_nano −
  query.observed_time_unix_nano`, both from the capture path, never ingest
  time. A negative or implausibly large RTT (clock skew, reordering) is
  clamped to unset and flagged with a `ParserWarning`.

## Event model (`proto/cloudflow/v1/dns.proto`)

The committed `dns.proto` mirrors the DHCP proto conventions:
preserve wire facts and a decoded view; reserve field numbers; enums for
well-known values. Wraps into the existing `CloudFlowEvent` oneof.

```proto
// One fully-correlated DNS transaction (query + its response) or, for the
// unmatched/unanswered event types, whichever half was seen.
message DnsTransactionEvent {
  // Both packet observations, when present. query/response are each a
  // standard PacketObservation (common.proto), so link/network/transport
  // metadata, capture time, VLAN, etc. come for free.
  PacketObservation query_packet = 1;
  PacketObservation response_packet = 2;

  DnsMessage query = 3;     // decoded query message (question, header)
  DnsMessage response = 4;  // decoded response message (answers, rcode)

  DnsLeg role = 5;          // CLIENT_FACING / BACKEND / RECURSION_UPSTREAM
  int64  rtt_nanos = 6;     // response.observed - query.observed; 0/unset if unmatched
  bool   rtt_valid = 7;

  // Correlation provenance for debugging: the key fields used to match.
  string transaction_key = 8;

  // Normalized identity, surfaced directly so sinks (and Splunk-metric
  // dimensioning) do not have to reach into query_packet.network. These are
  // the "who did this" fields for DNS per docs/event-model.md: for the
  // client-facing leg client_ip is the querying client; for the upstream leg
  // it is the recursor and server_ip is the authoritative it asked.
  string client_ip = 9;
  uint32 client_port = 10;
  string server_ip = 11;

  // Operator-assigned service role (WP-DNS11a) — an arbitrary label such as
  // dnsdist / recursor / authoritative, taken from config and keyed on the
  // server-side address (`server_ip`), or empty when that address is unmapped
  // or the server side is indeterminate. It is a config dimension only; it
  // does not change the leg `role`. A later WP routes the Splunk sourcetype by
  // it.
  string service_role = 12;

  repeated ParserWarning parser_warnings = 20;
}

enum DnsLeg {
  DNS_LEG_UNSPECIFIED = 0;
  DNS_LEG_CLIENT_FACING = 1;
  DNS_LEG_BACKEND = 2;
  DNS_LEG_RECURSION_UPSTREAM = 3;
  DNS_LEG_UNKNOWN = 4;
}

message DnsMessage {
  DnsHeader header = 1;
  repeated DnsQuestion questions = 2;     // usually exactly one
  repeated DnsResourceRecord answers = 3;
  repeated DnsResourceRecord authority = 4;
  repeated DnsResourceRecord additional = 5;
  DnsEdns edns = 6;                        // OPT pseudo-record, when present
  bytes raw_dns_payload = 20;              // subject to the D11-style size cap
  bool  raw_payload_truncated = 21;
}

message DnsHeader {
  uint32 id = 1;
  bool qr = 2; uint32 opcode = 3;
  bool aa = 4; bool tc = 5; bool rd = 6; bool ra = 7; bool ad = 8; bool cd = 9;
  uint32 rcode = 10;                       // extended rcode folds in EDNS bits
  uint32 qdcount = 11; uint32 ancount = 12; uint32 nscount = 13; uint32 arcount = 14;
}

message DnsQuestion {
  string qname = 1;          // presentation form, lowercased
  bytes  qname_wire = 2;     // raw, pre-normalization (preserves 0x20 casing)
  uint32 qtype = 3; string qtype_name = 4;
  uint32 qclass = 5;
}

message DnsResourceRecord {
  string name = 1;
  uint32 type = 2; string type_name = 3;
  uint32 class = 4;
  uint32 ttl = 5;
  bytes  rdata_raw = 6;
  string rdata_text = 7;     // best-effort decode for common types (A/AAAA/CNAME/NS/MX/TXT/SOA/PTR/SRV)
  bool   malformed = 8;
}

message DnsEdns {
  uint32 udp_payload_size = 1;
  uint32 extended_rcode = 2;
  uint32 version = 3;
  bool   do_bit = 4;         // DNSSEC OK
  repeated DnsEdnsOption options = 5;  // e.g. ECS (option 8), cookie (10)
}
```

`CloudFlowEvent.payload` gains `DnsTransactionEvent dns_transaction = 23;` (a
new field number; the DHCP oneof members keep theirs). `envelope.event_type`
is one of `dns.transaction.observed` / `dns.query.unanswered` /
`dns.response.unmatched`; `payload_schema = "cloudflow.v1.DnsTransactionEvent"`;
`source_type = "dns"`; `stream_name = "cloudflow:v1:wire:dns"`.

## Correlation stage (the pending table)

The heart of the source, specified for WP-DNS04.

- **Structure.** A bounded open-addressing hash table of pending queries,
  fixed capacity from config (`dns.pending_table_capacity`, default e.g.
  262144), keyed by the DNS-D6 key. Each entry holds the parsed query
  `DnsMessage`, its `PacketObservation`, the classified `role`, and the query
  `observed_time`. Memory is `capacity * sizeof(entry)` — documented and
  pre-allocated, no per-packet heap churn in steady state.
- **Insert.** On a parsed query, compute the key and insert. If the slot is
  occupied by a still-live different query (hash collision / port reuse before
  timeout), evict the older one as `dns.query.unanswered` (counted
  `dns_pending_evicted_collision_total`). If the table is at capacity, apply
  `dns.on_table_full` policy (default `drop_newest`, counted
  `dns_pending_drop_total`) — same explicit-policy discipline as the D9
  queues.
- **Match.** On a parsed response, swap endpoints, look up the key. Hit →
  emit `dns.transaction.observed` with `rtt_nanos`, remove the entry. Miss →
  emit `dns.response.unmatched` (counted `dns_response_unmatched_total`).
- **Timeout eviction.** A time-ordered index (ring or coarse timing wheel)
  evicts entries older than `dns.query_timeout_ms` (default 5000) as
  `dns.query.unanswered` (counted `dns_query_unanswered_total`). Eviction runs
  amortized on each insert and on a periodic tick so a quiet table still
  drains.
- **Threading.** The correlation stage is single-threaded and owns the table
  exclusively (no locking): the pipeline is
  `rx-reader → [pkt queue] → parse+correlate → [event queue] → redis-producer`,
  i.e. parse and correlate share one thread so the table needs no
  synchronization. If profiling later shows parse dominating, parsing can move
  ahead of a second queue, but v0.2 keeps it simple and correct.
- **Counters** (all in the stats line, DNS-D8): `dns_queries_parsed_total`,
  `dns_responses_parsed_total`, `dns_transactions_emitted_total` (by role),
  `dns_query_unanswered_total`, `dns_response_unmatched_total`,
  `dns_pending_table_depth` (gauge), `dns_pending_drop_total`,
  `dns_pending_evicted_collision_total`, `dns_rtt_invalid_total`,
  `dns_sampled_out_total`, `dns_tcp_partial_total`.

See `docs/failure-modes.md` for how these bounded-table failure modes fit
alongside the rest of the pipeline's loss accounting.

## Work packages

Sized for independent implementation by the same agent fleet, in dependency
order. `S/M/L` sizing as in `docs/architecture.md`.

| WP | Title | Depends on | Size |
|---|---|---|---|
| WP-DNS01 | `dns.proto` + codegen wiring | — (v0.1 codec) | S |
| WP-DNS02 | TCP-DNS decap helper (`cf_decap_tcp`, single-segment) in `cloudflow-packet` | v0.1 packet lib | M |
| WP-DNS03 | DNS message parser (`cf_dns_parse`: header, question, RR walk, EDNS, common rdata) + fixtures | WP-DNS01/02 | L |
| WP-DNS04 | Correlation stage (bounded pending table, RTT, eviction) | WP-DNS03 | L |
| WP-DNS05 | Leg classifier (local-IP auto-detect + config sets + direction cross-check) | WP-DNS03 | M |
| WP-DNS06 | DNS BPF filter + rx wiring (reuse WP-08 rx-reader; udp/tcp port 53, VLAN-aware) | v0.1 source | M |
| WP-DNS07 | `cloudflow-source-dns` app (config, stats, thread wiring, systemd, README) | WP-DNS04/05/06 | M |
| WP-DNS08 | Sink sourcetype mapping (`cloudflow:dns`) + fixtures; integration test through the real binaries | WP-DNS07, v0.1 sink | M |
| WP-DNS09 | DNS fixture corpus + parser fuzzing (single/multi-question, EDNS/ECS, truncation, compression loops, malformed) | WP-DNS03 | M |
| WP-DNS10 | Sampling/emit-policy engine (`dns.emit_policy`) | WP-DNS04 | S |

Suggested batches (each row parallel once the prior merged):

1. WP-DNS01
2. WP-DNS02, WP-DNS03 (parser can start against hand-built byte arrays)
3. WP-DNS04, WP-DNS05, WP-DNS09
4. WP-DNS06, WP-DNS10
5. WP-DNS07
6. WP-DNS08

Milestone **M-DNS1** (first correlated transaction end to end): WP-DNS01–07
plus the sink mapping — replay a query+response pcap pair, observe one
`dns.transaction.observed` with a sane `rtt_nanos` and `role` in
`cloudflow:v1:wire:dns`, decode it through the sink.

## Fixture and test policy

Same approach as the DHCP source (`docs/dhcp-source.md`): a committed scapy
generator produces deterministic, sanitized pcaps under
`tests/fixtures/dns/` using documentation address space (RFC 5737 / RFC
3849) — including **query+response pairs** so the correlation stage can be
driven end to end offline via the replay path, plus single packets for the
unanswered/unmatched cases. The correlation table gets its own unit tests
(insert/match/evict/timeout/collision, table-full policy) independent of
packet parsing.

## Non-goals (v0.2)

Explicitly out of scope; several are dstore's job, reinforcing the two-feed
model:

- **Client-query → upstream-fan-out stitching.** The recursor picks fresh
  IDs/ports for upstream queries, so the wire cannot reliably join "client
  asked X" to "recursor then asked these authoritatives." Correlate each leg
  independently; use dstore/recursor logs for the causal join.
- **Cache-hit accounting.** A cache hit emits no upstream traffic; wire RTT on
  the client leg is near-zero and there is no upstream leg to see. Cache-hit
  rate is a dstore metric.
- **Full TCP reassembly / AXFR/IXFR bodies** (DNS-D1).
- **DoH / DoT / DoQ** (DNS-D1) — encrypted, no wire payload to observe.
- **DNSSEC validation.** The `do`/`ad`/`cd` bits and RRSIG/DNSKEY records are
  captured as observed facts; CloudFlow does not validate signatures.
- **The dstore bridge itself.** The event model reserves room for an
  endpoint-observed DNS feed, but implementing a dnsdist-protobuf source is a
  separate future work package.
