# DHCP source

`cloudflow-source-dhcp` (v0.1, implemented) captures DHCPv4 and DHCPv6
traffic off the wire and turns it into `cloudflow.v1.CloudFlowEvent`s on
Redis Streams. It is destination-agnostic: nothing in it knows about Splunk.

```text
[rx-reader thread]                [event-formatter thread]              [redis-producer thread]
TPACKET_V3 ring, epoll     SPSC   decap (cloudflow-packet)      SPSC   hiredis pipeline
BPF: udp 67/68/546/547  -> q_pkt  DHCPv4/v6 parse            -> q_evt  XADD MAXLEN ~
copy frame + ts only              envelope + event_id                  reconnect/backoff
                                   protobuf pack
     cf_packet_item_t                      cf_event_item_t
```

Both queues are the bounded SPSC `cf_queue_t` (`libs/cloudflow-core`)
carrying the fixed-size item structs from `libs/cloudflow-core/cloudflow.h`.
Only the rx thread is hot-path constrained (no allocation, no syscalls
besides the ring/epoll); DHCP is low-rate, so the formatter and producer
favor clarity over throughput.

## Capture (`src/rx_reader.{h,c}`, `src/pcap_replay.{h,c}`)

Live capture uses `AF_PACKET`/`SOCK_RAW` with `PACKET_VERSION = TPACKET_V3`
and a block ring (`PACKET_RX_RING`; default 12 blocks x 4 MiB, 2048-byte
frames, all config-driven), `mmap`, and an epoll wait loop. The reader walks
each returned block (`tpacket_block_desc` → `num_pkts` → `tp_next_offset`)
and returns it to the kernel via `TP_STATUS_KERNEL`. It attempts `SCHED_FIFO`
priority and logs-and-continues if `CAP_SYS_NICE` is missing, and samples
`getsockopt(PACKET_STATISTICS)` for kernel-side drop counters.

A fixed, VLAN-aware cBPF program filters to UDP ports 67/68/546/547
in-kernel — plain and single-tagged 802.1Q frames both match. The
`capture.filter` config key is informational only: the builtin filter is
always used, and a mismatch is logged as a warning (D7 in
`docs/architecture.md`).

`pcap_replay_file()` reads a classic pcap file (either magic byte order, and
the nanosecond-timestamp variant) and pushes every frame into the same
queue, using the pcap record timestamps as `observed_time_unix_nano`. It
rejects pcapng files with a clear error and requires `DLT_EN10MB` (Ethernet)
framing. This is the mechanism behind `--replay <pcap>` and the integration
tests.

Per packet: `cf_packet_item_t` gets `observed_time_unix_nano` from the ring
or pcap timestamp, `packet_len`/`captured_len`, and the frame bytes (capped
at `CLOUDFLOW_PACKET_MAX_SIZE`, with a truncation flag set if the frame was
cut). The rx-reader does no parsing at all — it copies the frame and
timestamp and returns the block to the kernel (D10); all DHCP parsing
happens later in the formatter thread. On a full output queue it applies the
configured `on_full` policy (`drop_newest`, `drop_oldest`, or `block`; D9,
`docs/failure-modes.md`), counting every drop. Shutdown polls a 1000 ms
epoll timeout against the stop flag so the thread notices `cf_stop_notified()`
promptly.

Counters: `packets_received_total`, `packets_dropped_total` (kernel, from
`PACKET_STATISTICS`), `rx_queue_drop_total`, `rx_queue_depth` (gauge),
`packets_truncated_total`.

## Packet decap (`libs/cloudflow-packet/cf_decap.{h,c}`)

`cf_decap_udp()` walks Ethernet → (up to two VLAN tags, single-tag 802.1Q or
QinQ) → IPv4/IPv6 → UDP and fills a `cf_decap_udp_t` with link, network, and
transport metadata plus a zero-copy view of the UDP payload. It is pure
computation — no sockets, no allocation, no globals — so it runs identically
against ring frames and pcap-replayed ones, and every multi-byte field is
read via `memcpy` plus explicit byte-order conversion (never a pointer-cast
dereference into the frame, which would be undefined behavior on
misaligned input).

IPv6 extension headers (hop-by-hop, destination options, routing; bounded
depth) are walked to find the UDP header; a non-first fragment is reported
as `CF_DECAP_NOT_UDP` rather than guessed at. Truncated input, non-UDP
frames, and unsupported shapes (more than two VLAN tags, an extension-header
chain that runs too deep) each get a distinct result code so the formatter
can count them precisely rather than treat every non-DHCP packet the same
way.

`cf_ipfmt.{h,c}` provides reentrant MAC/IP formatting (`cf_format_mac`,
`cf_format_ip`) used when populating the envelope's `PacketObservation`.

## DHCPv4 and DHCPv6 parsing (`libs/cloudflow-packet/cf_dhcpv4*`, `cf_dhcpv6*`)

The parsers take the UDP payload (never the frame) and return a fully
populated `Cloudflow__V1__DhcpV4PacketEvent` / `...DhcpV6PacketEvent` tree
(`proto/cloudflow/v1/dhcp.proto`), each preserving three views of the same
observation:

- **Raw options** — every option in wire order, with duplicates preserved
  and each option's byte offset (`ordinal`) recorded. DHCPv4 option overload
  (option 52) is honored: when present, `sname`/`file` are walked as
  continued option space too. RFC 3396 long options are reassembled from
  their fragments before decoding (this is how `domain_search` and classless
  static routes often arrive split across multiple option-52 bytes).
- **Decoded options** — every field in `DhcpV4DecodedOptions` /
  `DhcpV6DecodedOptions`: vendor-specific suboptions (43, 17), relay-agent
  suboptions (82: circuit/remote/subscriber id), FQDN (81, both wire
  encodings), classless static routes (121/249), domain search (119, RFC
  1035 name compression scoped to the concatenated option data only — a
  compression pointer can never escape it), DHCPv6 DUIDs, IA_NA/IA_TA →
  IAADDR nesting into `assigned_addresses`, ORO codes, and vendor
  class/vendor-specific info with enterprise numbers. Option-name tables map
  `code -> canonical name` from IANA registries; an unknown code gets name
  `""`, never a guessed one.
- **Interpretation** — the derived operational view: `event_type` from the
  DHCP message type, `transaction_key` (`xid` hex + client MAC or client-id),
  `normalized_client_key`, `lease_address` (`yiaddr` for OFFER/ACK),
  `is_relayed` (`giaddr != 0`), and the best-effort `is_renewal`/`is_rebind`
  heuristic (a REQUEST with no server-id and no requested-ip: unicast means
  renewal, broadcast means rebind — inherently a `DERIVED`/`INFERRED`
  confidence signal, not an `OBSERVED` fact).

DHCPv6 relay messages (RELAY-FORW/RELAY-REPL) are parsed one level deep: the
outer message's options populate raw/decoded options and `event_type`
(`dhcpv6.relay-forw.observed` / `dhcpv6.relay-repl.observed`); the inner
client message inside the Relay Message option is preserved as raw option
bytes rather than recursively parsed.

**Malformed-input discipline ("trust the wire" applied to garbage).** Every
option read is bounds-checked against the remaining payload. A malformed
option sets `malformed = true` on that option, appends a `ParserWarning`
(a `code` like `"opt_len_overrun"`, a `field_path` like `"raw_options[3]"`,
and up to 16 bytes of raw context), and parsing **resynchronizes** at the
best available point and continues — a malformed packet is still a
reportable event, not a dropped one. The `v4_malformed_optlen.pcap` and
`v6_malformed_optlen.pcap` fixtures exercise exactly this: option-length
overruns that still decode to a `CloudFlowEvent` with `parser_warnings` set
and the correct message type when the header is intact. This is distinct
from an *undecodable* entry (protobuf decode failure at the sink) — see
`docs/failure-modes.md`.

`raw_dhcp_payload` always holds the input bytes at the parser level; the
final size decision (D11, below) is the formatter's job.

## Event formatter (`src/formatter.{h,c}`)

The middle thread — and the only place in the source that parses DHCP or
allocates (D10). `cf_format_packet()` is a pure function (frame in, packed
`CloudFlowEvent` out) used both by the thread loop and directly by tests:

1. Classify by UDP port: 67/68 → DHCPv4 parse, 546/547 → DHCPv6 parse.
   Anything else (BPF slippage, non-DHCP replay input) is counted
   (`packets_skipped_total`) and skipped, not treated as an error.
2. Populate the `EventEnvelope`: `event_id` via the deterministic hash (D5),
   `schema_version`, `source_type` (`"dhcpv4"`/`"dhcpv6"`),
   `observed_time_unix_nano` from the packet item, `ingest_time_unix_nano`
   from the current clock, `event_type` from the parser, `visibility =
   VISIBILITY_PACKET_PAYLOAD`, `confidence = OBSERVATION_CONFIDENCE_OBSERVED`,
   `payload_schema`, and `stream_name`.
3. Populate `PacketObservation` from the decap result (formatted MACs/IPs,
   `packet_len`/`captured_len`/`truncated`).
4. Pack with `protobuf-c`.

**D11 — oversize policy.** `CLOUDFLOW_EVENT_MAX_SIZE` is 8192 bytes: a fully
populated `DhcpV4PacketEvent` carries the raw payload plus every option
value twice (raw + decoded), which can exceed 4096 bytes on its own. If the
packed event exceeds the cap, the formatter drops `raw_dhcp_payload`, sets
`raw_payload_truncated = true`, and repacks; if it still does not fit, the
event is dropped and counted (`events_oversize_dropped_total`) rather than
truncating decoded fields, which would silently corrupt the interpretation.

Counters: `events_formatted_total` (by protocol), `packets_skipped_total`,
`parse_warnings_total`, `events_oversize_dropped_total`,
`formatter_queue_depth` (gauge), plus queue-full drops per policy.

## Redis producer

The formatter's output queue is drained by `libs/cloudflow-redis`'s
`cf_redis_producer`, a destination-agnostic `hiredis`-based pipelined `XADD`
writer shared by every source. See `docs/redis-streams.md` for the entry
format and `docs/failure-modes.md` for its reconnect/loss-accounting
behavior.

## Configuration and application (`src/config.{h,c}`, `src/main.c`)

`cloudflow-source-dhcp` loads a YAML config matching
`configs/examples/dhcp-source.yaml` (service, capture, queues, redis, stats
sections) via `libyaml`; unknown keys warn and are ignored, missing keys
default to that example file's values. Environment overrides layer on top:
`CF_REDIS_ENDPOINTS` (comma-separated, replaces `redis.endpoints`),
`CF_INTERFACE` (replaces `capture.interface`), `CF_SOURCE_HOST` (replaces
`service.source_host`). `capture.method` must be `rxring`; any other value
is a fatal config error. `capture.filter` and `redis.stream_dhcpv4`/
`stream_dhcpv6` are informational only, per D7 and the built-in stream
naming — a mismatch against the actual builtin behavior is warned, not
enforced.

`main.c` wires the three threads together in order — starts
`redis-producer`, then `event-formatter`, then `rx-reader` (or a pcap
replay) — runs a periodic structured stats line on the main thread every
`stats.interval_s` seconds (default 10), and shuts down in reverse order
(reader first, so both queues drain cleanly) on `SIGINT`/`SIGTERM`.

CLI: `-c <config>` (required), `--replay <pcap>` (runs the pcap reader
instead of the rx-ring, then drains and exits — this is the integration-test
and offline-replay mode), `--version`.

### systemd

`systemd/cloudflow-source-dhcp.service` runs the binary with
`-c /etc/cloudflow/dhcp-source.yaml`,
`AmbientCapabilities=CAP_NET_RAW CAP_SYS_NICE`, `NoNewPrivileges=yes`, and
`Restart=on-failure`.

## Fixture corpus (`tests/fixtures/dhcp/`)

Each fixture is a small, deterministically generated pcap (via
`tests/fixtures/dhcp/generate_fixtures.py`, using `scapy`) plus a
human-readable `<name>.expected.md`; the authoritative assertions live in
the C tests. Addresses come from documentation space only (IPv4
`192.0.2.0/24` / `198.51.100.0/24`, IPv6 `2001:db8::/32`, MACs
`02:00:5e:xx:xx:xx`) so fixtures are safe to commit.

```text
v4_discover.pcap            basic DISCOVER, opts 53/55/57/61
v4_offer.pcap                OFFER with subnet/router/dns/lease/T1/T2
v4_request_renewal.pcap     unicast REQUEST, no opt 50/54 (renewal heuristic)
v4_ack.pcap                  ACK with fqdn(81) + domain_search(119, compressed)
v4_nak.pcap                  NAK with message(56)
v4_relayed_ack.pcap          giaddr set + option 82 circuit/remote id
v4_vlan_discover.pcap        802.1Q tagged DISCOVER (exercises the decap layer too)
v4_overload.pcap             option 52, options continued in sname/file
v4_long_option.pcap          RFC3396 split option 121 + valid CSR decode
v4_malformed_optlen.pcap     option length overruns payload
v4_no_msgtype.pcap           BOOTP-ish packet without option 53
v6_solicit.pcap              SOLICIT with client DUID + ORO + IA_NA
v6_advertise.pcap            ADVERTISE with IA_NA/IAADDR
v6_request.pcap              REQUEST
v6_reply.pcap                REPLY with assigned address + server DUID
v6_relay_forw.pcap           RELAY-FORW wrapping a SOLICIT
v6_vendor_opts.pcap          option 17 with enterprise + suboptions
v6_malformed_optlen.pcap     option length overruns payload
```

Fixture-driven CUnit tests assert field values for each fixture and confirm
malformed-option fixtures parse without crashing, produce warnings, and
still yield the correct message type when the header is intact. Fuzz
harnesses for the decap layer and both parsers live under `tests/fuzz/`; see
`docs/building-and-testing.md`.
