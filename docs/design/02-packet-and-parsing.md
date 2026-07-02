# Packet decap and DHCP parsers

Work packages WP-05, WP-06, WP-07 plus the fixture corpus they share. These
produce `libs/cloudflow-packet/`, the library that turns raw frames into
populated protobuf messages. Everything here is pure computation: no sockets,
no Redis, no threads — which is what makes it easy to test exhaustively and
safe to hand to independent implementers.

The protobuf messages being populated are the contract; read
`proto/cloudflow/v1/common.proto` and `proto/cloudflow/v1/dhcp.proto`
carefully before starting.

---

## WP-05 — Packet decap library

**Goal.** Parse Ethernet → (VLAN) → IPv4/IPv6 → UDP and expose both the UDP
payload and the metadata needed to fill `cloudflow.v1.PacketObservation`.

**Reuse.** The eth/IP/UDP walk in `import/network_syslog_collector/src/rx-ring.c`
(`handle_packet`) shows the shape but trusts BPF and asserts; this library
must instead fail soft (return error) because it also runs on pcap replay
input that BPF never filtered. The VLAN handling in
`import/network_dhcp_collector/src/main.c` shows single-tag 802.1Q parsing;
support one or two tags (QinQ: outer `0x88a8` or `0x8100`).

**Deliverables** (under `libs/cloudflow-packet/`):

- `cf_decap.h/.c`:
  ```c
  typedef struct {
      // link
      uint8_t  src_mac[6], dst_mac[6];
      uint32_t vlan_ids[2];
      uint8_t  vlan_count;
      uint16_t ethertype;              // inner, after VLAN tags
      // network
      uint8_t  ip_version;             // 4 or 6
      uint8_t  src_ip[16], dst_ip[16]; // v4 in first 4 bytes
      uint8_t  next_header;            // protocol / next-header
      uint8_t  ttl_or_hop_limit;
      uint8_t  dscp, ecn;
      uint8_t  fragmented;             // first-fragment or fragmented flag set
      uint16_t fragment_offset;
      // transport (UDP only in v0.1)
      uint16_t src_port, dst_port;
      uint16_t udp_length;
      uint8_t  udp_checksum_present;
      // payload view into the input frame (no copy)
      const uint8_t *payload;
      size_t payload_len;
  } cf_decap_udp_t;

  typedef enum {
      CF_DECAP_OK = 0,
      CF_DECAP_NOT_UDP,        // valid frame, not UDP (or fragmented non-first)
      CF_DECAP_TRUNCATED,      // frame shorter than headers claim
      CF_DECAP_UNSUPPORTED,    // not IPv4/IPv6, >2 VLAN tags, IPv6 ext chain too deep
  } cf_decap_result_t;

  cf_decap_result_t cf_decap_udp(const uint8_t *frame, size_t frame_len,
                                 cf_decap_udp_t *out);
  ```
- `cf_ipfmt.h/.c` — reentrant address/MAC formatting (the legacy helpers use
  static buffers; do not copy that):
  ```c
  void cf_format_mac(char out[18], const uint8_t mac[6]);
  void cf_format_ip(char out[46], uint8_t ip_version, const uint8_t ip[16]);
  ```

**Rules.**
- Every multi-byte field read via `memcpy` + explicit byte-order conversion;
  no pointer-cast dereferences into the frame (alignment/UB).
- IPv6: walk hop-by-hop/dest-options/routing extension headers (bounded, max
  8) to find UDP; fragment header → treat non-first fragments as
  `CF_DECAP_NOT_UDP` and set `fragmented` on first fragments.
- No allocation, no globals; safe for any thread.

**Acceptance criteria.**
- CUnit tests from hand-built byte arrays: plain v4, single VLAN, QinQ,
  plain v6, v6 with one extension header, truncation at every header boundary
  (loop over lengths 0..full asserting no crash and sane result codes),
  non-UDP, fragments.
- Fuzz harness `tests/fuzz/decap_fuzz.c` (AFL pattern from legacy
  `tests/filter_fuzz_test.c` and `tests/Fuzzing.md`): feed a file as a frame,
  assert no crash. Not required to run in CI; required to exist and build.

---

## Shared parser conventions (WP-06 and WP-07)

- Input is the UDP payload (`cf_decap_udp_t.payload`); the parser never sees
  the frame.
- Output is a heap-allocated protobuf-c message tree the caller frees via the
  matching `cloudflow__v1__dhcp_v4_packet_event__free_unpacked`-style helper
  or a provided `_destroy` function. Per D10 this runs in the formatter
  thread, so allocation is acceptable; still prefer one arena-ish upfront
  allocation where easy.
- **Never trust lengths.** Every option read is bounds-checked against the
  remaining payload. A malformed option sets `malformed = true` on that
  option, appends a `ParserWarning` (with `code` like
  `"opt_len_overrun"`, `field_path` like `"raw_options[3]"`, and up to 16
  bytes of `raw_context`), and parsing **continues** at the best resync point.
  A malformed packet is still an event — "trust the wire" means reporting what
  was actually seen, including garbage.
- Parsers return the derived `event_type` string (e.g.
  `"dhcpv4.discover.observed"`); the formatter puts it in the envelope. The
  event-type vocabulary is the list in `README.md` (Event model section);
  packets whose message type is unknown/absent use
  `"dhcpv4.packet.observed"` / `"dhcpv6.packet.observed"`.
- Option-name tables (`code -> canonical name`) live in one `.c` table per
  protocol with names from IANA registries; unknown codes get name `""`, never
  a guess.

**Reuse.** `process_dhcpv4` / `process_dhcpv6` in
`import/network_dhcp_collector/src/main.c` (and the more verbose variants in
`src/test.c`) are correct-shaped TLV walks with pad/end handling and
`memcpy` discipline — lift the walk logic, then extend per below. Their output
code (printf) is discarded.

---

## WP-06 — DHCPv4 parser

**Goal.** UDP payload → fully populated `cloudflow.v1.DhcpV4PacketEvent`
(header, raw_options, decoded, interpretation, parser_warnings, raw payload).

**Deliverables** (under `libs/cloudflow-packet/`):

- `cf_dhcpv4.h/.c`:
  ```c
  // Returns NULL only on allocation failure or payload too short to contain
  // a BOOTP fixed header; *event_type receives a static string.
  Cloudflow__V1__DhcpV4PacketEvent *
  cf_dhcpv4_parse(const uint8_t *payload, size_t len,
                  const char **event_type);
  void cf_dhcpv4_event_free(Cloudflow__V1__DhcpV4PacketEvent *ev);
  ```
  (`packet`, i.e. the `PacketObservation`, is attached by the formatter, not
  here.)

**Required behavior**, mapping to `dhcp.proto`:

- Fixed header: all fields; `chaddr_mac` only when `htype==1 && hlen==6`;
  `sname_text`/`file_text` only when printable ASCII, raw bytes always.
  `magic_cookie_present` from the 4 bytes after `file`.
- Raw options: wire order, `ordinal` per source field, duplicates preserved.
  Option overload (option 52): when present, also walk `sname`/`file` per its
  value with `source_field` set accordingly.
- Long options (RFC 3396): mark each fragment `long_option_fragment = true` in
  raw_options; for decoding, concatenate fragments of the same code before
  interpreting (this is how `domain_search` and CSR options often arrive).
- Decoded options: every field in `DhcpV4DecodedOptions`, including
  option 43 suboption walk keyed off option 60 where recognizable, option 82
  suboptions (circuit/remote/subscriber id), option 81 FQDN (flags, rcodes,
  both wire encodings of the domain), options 121/249 classless routes
  (prefix-packed destination decoding), option 119 domain search (RFC 1035
  compression **within the concatenated option data only** — pointers must not
  escape it), option 252 WPAD.
- Interpretation: `event_type` from message type; `transaction_key` =
  `xid` hex + `chaddr_mac` (or client-id hex when no MAC);
  `normalized_client_key` = client-id if present else MAC;
  `lease_address` = `yiaddr` for OFFER/ACK; `is_relayed` = `giaddr != 0`;
  `is_broadcast` from flags bit 15; `is_renewal`/`is_rebind` best effort:
  REQUEST with no server-id and no requested-ip, unicast → renewal,
  broadcast → rebind (document this heuristic in a comment; confidence for
  these two bools is inherently DERIVED).
- `raw_dhcp_payload` = input bytes, subject to the D11 size policy (the
  formatter enforces the final cap; the parser always includes it).
- `DhcpV4LeaseEvent` is **not** emitted in v0.1 (reserved for a future
  correlation stage).

**Acceptance criteria.**
- Fixture-driven tests (see corpus below): for each fixture pcap there is an
  expected-JSON file; the test parses, converts to canonical JSON via
  `protobuf-c`'s... (no JSON in protobuf-c) — instead: expected values are
  asserted field-by-field in C for a core set, **and** a fixture round-trip
  binary writes packed protobuf to disk that the Python check in WP-13's
  `decode-event` can decode; keep the C assertions authoritative.
- Malformed-option fixtures parse without crashing, produce warnings, and
  still yield the correct message type when it is intact.
- Fuzz harness `tests/fuzz/dhcpv4_fuzz.c` builds; 10-minute local AFL run
  documented as performed in the PR (no CI requirement).

---

## WP-07 — DHCPv6 parser

**Goal.** UDP payload → `cloudflow.v1.DhcpV6PacketEvent`, including relay
message handling.

**Deliverables** (under `libs/cloudflow-packet/`):

- `cf_dhcpv6.h/.c` mirroring the WP-06 API (`cf_dhcpv6_parse`,
  `cf_dhcpv6_event_free`).

**Required behavior:**

- Header: message type enum mapping per `dhcp.proto`; 24-bit transaction id
  for client/server messages; hop-count/link-address/peer-address for
  RELAY-FORW/RELAY-REPL.
- For relay messages, the inner client message lives in the Relay Message
  option (9): v0.1 parses the **outer** message's options into
  raw_options/decoded (the inner message appears as the raw option bytes) and
  sets event_type from the outer type (`dhcpv6.relay-forw.observed`,
  `dhcpv6.relay-repl.observed` — add these two to the vocabulary; recursive
  inner parsing is a later enhancement and the raw bytes preserve it).
- Raw options: all, wire order, 2-byte code/len, bounds-checked, nested
  options **not** recursed except as required for decoded fields below.
- Decoded options per `DhcpV6DecodedOptions`: client DUID (1), server DUID
  (2), assigned addresses from IA_NA/IA_TA → IAADDR nesting (walk IA options
  one level deep to collect addresses into `assigned_addresses`), ORO (6)
  codes, vendor class (16), vendor-specific info (17) with enterprise number
  and suboption walk.
- Event types: solicit/advertise/request/confirm/renew/rebind/reply/release/
  decline/reconfigure/information-request map to
  `dhcpv6.<name>.observed`; unknown → `dhcpv6.packet.observed`.

**Acceptance criteria.** Same structure as WP-06: fixture-driven field
assertions, malformed-option robustness, fuzz harness builds. Update
`README.md`'s event-class list and `docs/event-model.md` with the two relay
event types.

---

## Fixture corpus (shared by WP-06/07, referenced by WP-14)

Location: `tests/fixtures/dhcp/`. Each fixture is a small pcap plus a
`<name>.expected.md` describing the asserted fields (human-readable; the
authoritative assertions live in the C tests). Fixtures are **generated, not
captured**: a committed `tests/fixtures/dhcp/generate_fixtures.py` (scapy)
builds them deterministically so they are guaranteed sanitized. Address
policy: IPv4 from 192.0.2.0/24 and 198.51.100.0/24, IPv6 from 2001:db8::/32,
MACs from 02:00:5e:xx:xx:xx.

Minimum corpus:

```text
v4_discover.pcap            basic DISCOVER, opts 53/55/57/61
v4_offer.pcap               OFFER with subnet/router/dns/lease/T1/T2
v4_request_renewal.pcap     unicast REQUEST, no opt 50/54 (renewal heuristic)
v4_ack.pcap                 ACK with fqdn(81) + domain_search(119, compressed)
v4_nak.pcap                 NAK with message(56)
v4_relayed_ack.pcap         giaddr set + option 82 circuit/remote id
v4_vlan_discover.pcap       802.1Q tagged DISCOVER (exercises WP-05 too)
v4_overload.pcap            option 52, options continued in sname/file
v4_long_option.pcap         RFC3396 split option 121 + valid CSR decode
v4_malformed_optlen.pcap    option length overruns payload
v4_no_msgtype.pcap          BOOTP-ish packet without option 53
v6_solicit.pcap             SOLICIT with client DUID + ORO + IA_NA
v6_advertise.pcap           ADVERTISE with IA_NA/IAADDR
v6_request.pcap             REQUEST
v6_reply.pcap               REPLY with assigned address + server DUID
v6_relay_forw.pcap          RELAY-FORW wrapping a SOLICIT
v6_vendor_opts.pcap         option 17 with enterprise + suboptions
v6_malformed_optlen.pcap    option length overruns payload
```
