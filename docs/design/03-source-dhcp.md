# cloudflow-source-dhcp

Work packages WP-08 through WP-11: the capture module, the Redis producer
library, the event formatter, and the application that wires them together.

Thread/data model (D4, D10):

```text
[rx-reader thread]                [event-formatter thread]              [redis-producer thread]
TPACKET_V3 ring, epoll     SPSC   decap (WP-05)                  SPSC   hiredis pipeline
BPF: udp 67/68/546/547  -> q_pkt  dhcp parse (WP-06/07)       -> q_evt  XADD MAXLEN ~
copy frame + ts only              envelope + event_id                   reconnect/backoff
                                  protobuf pack
     cf_packet_item_t                      cf_event_item_t
```

Both queues are `cf_queue` (WP-04) carrying the fixed-size item structs from
`libs/cloudflow-core/cloudflow.h`. Only the rx thread is hot-path constrained
(no allocation, no syscalls besides the ring/epoll); DHCP rates are low, so
the formatter and producer favor clarity.

---

## WP-08 — rx-reader capture module

**Goal.** Capture DHCP frames into `cf_packet_item_t`s pushed to a `cf_queue`,
with kernel-level filtering and drop accounting. Also provide a pcap replay
input that feeds the same queue, for tests and offline use.

**Reuse.** This WP is mostly a lift of
`import/network_syslog_collector/src/rx-ring.c`: socket setup
(`PF_PACKET`/`SOCK_RAW`), `PACKET_VERSION = TPACKET_V3`, block ring
(`PACKET_RX_RING`, start at 12 blocks x 4 MiB, 2048-byte frames — make block
count/size config-driven), `mmap`, epoll wait loop, the **block walk**
(`tpacket_block_desc` -> `num_pkts` -> `tp_next_offset`), returning blocks via
`TP_STATUS_KERNEL`, `SCHED_FIFO` priority attempt (log-and-continue if
`CAP_SYS_NICE` is missing), and `getsockopt(PACKET_STATISTICS)` for kernel
drop counters. Replace its BPF program with the VLAN-aware DHCP filter from
`import/network_dhcp_collector/src/main.c` (`attach_bpf`, accepting UDP dst
or src port 67/68/546/547 for plain and single-tagged 802.1Q frames). The
pcap replay reader is a lift of `import/network_dhcp_collector/src/replay.c`
(add pcapng rejection with a clear error; classic pcap only, DLT_EN10MB).
**Do not** copy the frame-walk from `import/network_dhcp_collector/src/ring.c`
(incorrect for TPACKET_V3).

**Deliverables** (under `sources/cloudflow-source-dhcp/src/`):

- `rx_reader.h/.c`:
  ```c
  typedef struct {
      const char *interface_name;   // NULL/"" = all interfaces
      uint32_t block_size, block_count, frame_size;
      cf_queue_t *out;              // of cf_packet_item_t
      cf_source_stats_t *stats;     // WP-11 owns the struct
      cf_queue_full_policy_t on_full;   // D9
  } rx_reader_config_t;

  int  rx_reader_start(const rx_reader_config_t *cfg);  // spawns the thread
  void rx_reader_stop(void);                            // joins; idempotent
  ```
- `pcap_replay.h/.c`:
  ```c
  // Pushes every frame of a classic pcap file into out, using the pcap
  // record timestamps as observed_time_unix_nano. Synchronous; returns
  // frame count or -1.
  long pcap_replay_file(const char *path, cf_queue_t *out,
                        cf_source_stats_t *stats);
  ```

**Behavior.**
- Per packet: fill `cf_packet_item_t` — `observed_time_unix_nano` from
  `tp_sec`/`tp_nsec`, `packet_len`/`captured_len` from the ring header,
  frame bytes capped at `CLOUDFLOW_PACKET_MAX_SIZE` (set a truncation bit in
  `flags`; define flag constants in `cloudflow.h`), then `cf_queue_push`.
- On full queue apply `on_full`: `drop_newest` (skip, count),
  `drop_oldest` (pop one, count, push), or `block` (bounded retry loop with
  `cf_sleep_ns`, still checking `cf_stop_notified`).
- Counters (into the app's stats struct): `packets_received_total`,
  `packets_dropped_total` (kernel, from PACKET_STATISTICS, sampled per stats
  interval), `rx_queue_drop_total` (ours), `rx_queue_depth` (gauge sampled at
  stats time), `packets_truncated_total`.
- Clean shutdown: epoll timeout 1000 ms, loop checks `cf_stop_notified()`.

**Acceptance criteria.**
- Unit: pcap replay of `tests/fixtures/dhcp/v4_discover.pcap` yields exactly
  one queued item with correct timestamp, lengths, and leading bytes.
- Manual (documented in PR, not CI): run with `CAP_NET_RAW` on a veth pair,
  inject DHCP + non-DHCP traffic with scapy, verify only DHCP arrives and
  kernel stats report the filtering. Include the exact commands used.
- Queue-full behavior test: tiny queue, replay many frames, assert counts per
  policy.

---

## WP-09 — Redis XADD producer library

**Goal.** A reusable library (`libs/cloudflow-redis/`) that drains
`cf_event_item_t`s from a queue and delivers them to Redis Streams with
pipelining, reconnect, and explicit loss accounting. Destination-agnostic:
nothing DHCP-specific in here.

**Reuse.** Structure lifted from `import/network_syslog_collector/src/redis.c`:
the pipeline-accumulate-then-drain loop (`redis_queue_handler`), flush on
count-or-age, reconnect with rate-limited retry, and drop accounting. Changes:
single thread (D4) instead of N workers; plain `hiredis` instead of
`hiredis-cluster` (D3); binary-safe payloads.

**Deliverables** (under `libs/cloudflow-redis/`):

- `cf_redis_producer.h/.c`:
  ```c
  typedef struct {
      const char *const *endpoints;    // "host:port", tried in order (D3)
      size_t endpoint_count;
      long long maxlen_approx;         // XADD MAXLEN ~ value; 0 = no trim
      uint32_t pipeline_max;           // default 512
      uint32_t flush_interval_ms;      // default 100
      cf_queue_t *in;                  // of cf_event_item_t
      cf_redis_stats_t *stats;
  } cf_redis_producer_config_t;

  int  cf_redis_producer_start(const cf_redis_producer_config_t *cfg);
  void cf_redis_producer_stop(void);   // flushes pipeline, joins
  ```

**Behavior.**
- Entry format per `docs/redis-streams.md` — for each item:
  ```text
  XADD <stream> MAXLEN ~ <maxlen> * schema cloudflow.v1.CloudFlowEvent
       version 1 encoding protobuf event_type <item.event_type>
       payload <item.payload bytes>
  ```
  Stream name from `cf_stream_name(item.stream_id)`. Use `redisAppendCommand`
  with `%b` for the payload (binary-safe, embedded NULs). `event_type` rides
  along as a plain-text field for debugging/routing per `envelope.proto`'s
  comment.
- Pipeline: append up to `pipeline_max` or until `flush_interval_ms` since
  first unflushed append, then drain replies; a reply of error type
  increments `xadd_errors_total` and logs (rate-limited) but does not stop the
  loop.
- Connect: try endpoints in order with a connect timeout (3 s); on
  disconnect/IO error, free context, reconnect with backoff 100 ms doubling
  to 5 s cap, cycling endpoints. While disconnected the input queue fills and
  the *upstream* policy applies — this library never buffers beyond its
  in-flight pipeline. Items in a failed pipeline whose replies were never
  received are **retried once** after reconnect (keep the unacked slice);
  double-delivery is acceptable (dedupe is downstream's job via `event_id`),
  silent loss is not — if the retry also fails, count `events_lost_total` and
  drop.
- Counters: `xadd_total`, `xadd_errors_total`, `xadd_latency_ns_total` (sum,
  for avg), `redis_reconnects_total`, `events_lost_total`,
  `redis_queue_depth` gauge.
- Shutdown: drain queue up to a 5 s deadline, flush, then exit.

**Acceptance criteria.**
- Integration-style unit test (requires local Redis; guarded by env var
  `CF_TEST_REDIS=host:port`, skipped otherwise): push N items across both
  DHCP streams, assert `XLEN` totals, entry field names/values, and payload
  byte-for-byte round-trip.
- Reconnect test: same but restart Redis (or kill the connection via
  `CLIENT KILL`) mid-run; assert no events silently lost (delivered +
  events_lost_total == pushed).
- `make bench` hook (WP-15 fleshes out): sustained XADD of 4 KiB payloads,
  report events/sec.

---

## WP-10 — Event formatter

**Goal.** The middle thread: pop `cf_packet_item_t`, decap (WP-05), parse
(WP-06/07), build the `CloudFlowEvent` envelope, pack protobuf into a
`cf_event_item_t`, push.

**Deliverables** (under `sources/cloudflow-source-dhcp/src/`):

- `formatter.h/.c`:
  ```c
  typedef struct {
      const char *source_host;       // config; default gethostname()
      const char *source_instance;
      const char *capture_interface;
      const char *observation_method;  // "rxring" or "pcap-replay"
      cf_queue_t *in;                // cf_packet_item_t
      cf_queue_t *out;               // cf_event_item_t
      cf_source_stats_t *stats;
      cf_queue_full_policy_t on_full;
  } formatter_config_t;

  int  formatter_start(const formatter_config_t *cfg);
  void formatter_stop(void);
  ```
  Plus a pure function used by the thread and by tests:
  ```c
  // Returns 0 on success; fills item. Non-DHCP/undecodable packets return
  // CF_FORMAT_SKIP and are counted, not errored.
  int cf_format_packet(const formatter_config_t *cfg,
                       const cf_packet_item_t *pkt,
                       cf_event_item_t *item);
  ```

**Behavior.**
- Classification after decap: dst or src port 67/68 → DHCPv4 parse; 546/547 →
  DHCPv6 parse. Anything else (BPF slippage, replay input): count
  `packets_skipped_total`, skip.
- Envelope population (see `envelope.proto`): `event_id` via `cf_event_id`
  (D5); `schema_version = 1`; `source_type` = "dhcpv4"/"dhcpv6";
  `observed_time_unix_nano` from the packet item; `ingest_time_unix_nano` =
  `cf_now_unix_nano()`; `event_type` from the parser; `visibility =
  VISIBILITY_PACKET_PAYLOAD`; `confidence = OBSERVATION_CONFIDENCE_OBSERVED`;
  `payload_schema` = `"cloudflow.v1.DhcpV4PacketEvent"` /
  `"...DhcpV6PacketEvent"`; `stream_name` via `cf_stream_name()`.
- `PacketObservation` populated from `cf_decap_udp_t` (formatted MACs/IPs via
  `cf_ipfmt`), `packet_len`/`captured_len`/`truncated` from the item.
- Pack with protobuf-c into `item.payload`. If packed size >
  `CLOUDFLOW_EVENT_MAX_SIZE`, apply D11: clear `raw_dhcp_payload`, set
  `raw_payload_truncated`, repack; if still too large, count
  `events_oversize_dropped_total` and skip.
- Counters: `events_formatted_total` (by protocol), `packets_skipped_total`,
  `parse_warnings_total`, `events_oversize_dropped_total`,
  `formatter_queue_depth` gauge, queue-full drops per policy.

**Acceptance criteria.**
- Unit tests drive `cf_format_packet` with fixture frames end-to-end
  (frame in → packed `CloudFlowEvent` out → unpack → assert envelope fields,
  event_id determinism across two runs, payload oneof correctness).
- Oversize test: a synthetic maximal-options packet triggers the D11
  truncation path and yields a decodable event with `raw_payload_truncated`.

---

## WP-11 — Source application

**Goal.** `cloudflow-source-dhcp` binary: config load, thread wiring, stats
reporting, signals, systemd integration.

**Deliverables** (under `sources/cloudflow-source-dhcp/`):

- `src/config.h/.c` — loads the YAML schema of
  `configs/examples/dhcp-source.yaml` via libyaml (flat mapping walk; unknown
  keys warn, missing keys get defaults from that example file's values).
  Env overrides: `CF_REDIS_ENDPOINTS` (comma-separated), `CF_INTERFACE`,
  `CF_SOURCE_HOST`. CLI: `-c <config>`, `--replay <pcap>` (runs pcap_replay
  instead of rx_reader, then drains and exits — this is the integration-test
  mode), `--version`.
  The `capture.filter` key is informational in v0.1 (D7): log a warning that
  the builtin BPF is used. The `capture.method` key accepts only `rxring`.
- `src/stats.c/.h` — `cf_source_stats_t` (all counters named in WP-08/09/10,
  `AGENTS.md` metric names where they exist) and a stats loop on the main
  thread: every `stats.interval_s` (config, default 10) emit one `cf_log`
  line with all counters/gauges; on `stats.reset_on_report: false` (default)
  counters are cumulative.
- `src/main.c` — lifecycle exactly like the legacy
  `import/network_syslog_collector/src/main.c`: parse config →
  `cf_log_init` → init queues (capacities from config) →
  `cf_redis_producer_start` → `formatter_start` → `rx_reader_start` (or
  replay) → stats loop until `cf_stop_notified` → stop in reverse order
  (reader first so queues drain), exit code from the stop reason.
- `systemd/cloudflow-source-dhcp.service` — update the existing unit:
  `AmbientCapabilities=CAP_NET_RAW CAP_SYS_NICE`, `NoNewPrivileges=yes`,
  `Restart=on-failure`, config path `/etc/cloudflow/dhcp-source.yaml`.
- Update `sources/cloudflow-source-dhcp/README.md` with build/run/replay
  instructions and the metrics list.

**Acceptance criteria.**
- `cloudflow-source-dhcp --replay tests/fixtures/dhcp/v4_discover.pcap` with
  a local Redis produces exactly one entry in `cloudflow:v1:wire:dhcpv4`
  whose payload decodes (this becomes the core of WP-14's integration test,
  and is milestone M1's source half).
- Config-file parse errors and unreachable-Redis-at-startup produce a clear
  structured error and nonzero exit (fail fast at startup; reconnect logic
  only governs established runtime).
- `kill -TERM` during replay exits 0 within 6 s with queues drained.
