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

## WP-11: the `cloudflow-source-dhcp` application

`src/config.{h,c}`, `src/stats.{h,c}`, and `src/main.c` wire the three
pipeline stages together into the runnable binary
(`build/cloudflow-source-dhcp`). It loads a YAML config (D6), initializes the
two bounded SPSC queues, starts the redis-producer, event-formatter, and
rx-reader (or a pcap replay), runs a periodic structured stats line on the
main thread, and shuts down in reverse pipeline order (reader first so the
queues drain, then formatter, then producer).

### Build

```sh
make -C sources/cloudflow-source-dhcp all    # builds the .a AND the binary
make -C sources/cloudflow-source-dhcp test   # CUnit suites (rx_reader, formatter)
make -C sources/cloudflow-source-dhcp clean
```

`all` builds both `build/libcloudflow-source-dhcp.a` and
`build/cloudflow-source-dhcp`. The binary links the source library plus
`libcloudflow-redis.a`, `libcloudflow-packet.a`, `libcloudflow-codec.a`,
`libcloudflow-core.a`, and `hiredis` / `protobuf-c` / `yaml`.

### Run (live capture)

Needs `CAP_NET_RAW` (see D7 / the veth section above); `CAP_SYS_NICE` is
optional (SCHED_FIFO attempt, degrades gracefully). Config path via `-c`:

```sh
sudo build/cloudflow-source-dhcp -c /etc/cloudflow/dhcp-source.yaml
```

The config schema is `configs/examples/dhcp-source.yaml`. Unknown keys are
warned and ignored; missing keys default to that example file's values.
`capture.method` must be `rxring` (any other value is a fatal error).
`capture.filter` is informational only in v0.1 (D7): the builtin VLAN-aware
DHCP cBPF filter is always used, and a warning is logged noting this.
`redis.stream_dhcpv4`/`stream_dhcpv6` are informational too (the producer
uses the built-in stream names); a mismatch is warned.

### Replay a pcap (integration / M1 mode)

`--replay <pcap>` swaps the rx-reader for a synchronous pcap read, then
drains both queues (bounded deadline) and exits 0 — this is milestone M1's
source half and the core of WP-14's integration test. `-c` is still required
(the config supplies redis endpoints, queue sizing, etc.):

```sh
build/cloudflow-source-dhcp --replay tests/fixtures/dhcp/v4_discover.pcap \
    -c /etc/cloudflow/dhcp-source.yaml
# then, against the configured Redis:
redis-cli XLEN cloudflow:v1:wire:dhcpv4     # => 1
redis-cli XRANGE cloudflow:v1:wire:dhcpv4 - +
# entry fields: schema version encoding event_type payload
```

`--version` prints the version and exits; `-h`/`--help` prints usage.

### Environment overrides

Applied on top of the loaded YAML (D6):

| Env var | Effect |
|---|---|
| `CF_REDIS_ENDPOINTS` | comma-separated `host:port` list, replaces `redis.endpoints` |
| `CF_INTERFACE` | replaces `capture.interface` |
| `CF_SOURCE_HOST` | replaces `service.source_host` (else `gethostname()`) |

### Metrics

One structured JSON stats line is emitted every `stats.interval_s` seconds
(default 10), plus once more at shutdown. It carries every pipeline counter
and gauge (D8), with the metric names from `AGENTS.md`:

- rx-reader / pcap-replay: `packets_received_total`, `packets_dropped_total`
  (kernel), `rx_queue_drop_total`, `rx_queue_depth` (gauge),
  `packets_truncated_total`
- event-formatter: `events_formatted_total`,
  `events_formatted_dhcpv4_total`, `events_formatted_dhcpv6_total`,
  `packets_skipped_total`, `parse_warnings_total`,
  `events_oversize_dropped_total`, `formatter_queue_depth` (gauge),
  `formatter_queue_drop_total`
- redis-producer (from `cf_redis_stats_t`): `redis_queue_depth` (gauge),
  `xadd_total`, `xadd_errors_total`, `events_lost_total`,
  `redis_reconnects_total`, `xadd_avg_latency_ns` (derived from
  `xadd_latency_ns_total / xadd_total`)

With `stats.reset_on_report: true` the counters are read-and-zeroed each line
(deltas); the default (`false`) reports cumulative counters. Gauges are
always sampled live.

### systemd

`systemd/cloudflow-source-dhcp.service` runs the binary with
`-c /etc/cloudflow/dhcp-source.yaml`, `AmbientCapabilities=CAP_NET_RAW
CAP_SYS_NICE`, `NoNewPrivileges=yes`, and `Restart=on-failure`.

## WP-08: rx-reader capture module + pcap replay

`src/rx_reader.{h,c}` and `src/pcap_replay.{h,c}` implement the first stage
of the pipeline (see `docs/dhcp-source.md`'s WP-08 section for the
full spec). Both feed `cf_packet_item_t`s (raw frame bytes plus the ring/pcap
timestamp -- no parsing, per D10) into a `cf_queue_t`, applying the D9
`on_full` backpressure policy (`src/queue_policy.h`) on every push. Supporting
types (`cf_source_stats_t`, `cf_queue_full_policy_t`) live in
`src/source_stats.h`/`src/queue_policy.h` so they can be shared with the
WP-10 event-formatter and WP-11 application without a circular include.

### Build and test

```sh
make -C sources/cloudflow-source-dhcp all    # build/libcloudflow-source-dhcp.a
make -C sources/cloudflow-source-dhcp test   # CUnit suite (tests/rx_reader_test.c)
make -C sources/cloudflow-source-dhcp clean
```

The CUnit suite is offline-only: pcap replay behavior (single-packet fixture
round-trip, queue-full drop accounting per policy, pcapng rejection) and
`cf_queue_push_policy` directly (all three policies, including block-mode
unblocking via a draining consumer thread). It needs no capture
capabilities and runs in ordinary CI.

### Replaying a capture offline

```c
#include "pcap_replay.h"

long n = pcap_replay_file("tests/fixtures/dhcp/v4_discover.pcap",
                           &out_queue, &stats, CF_ONFULL_DROP_NEWEST);
```

`pcap_replay_file()` accepts classic pcap only (both magic byte orders, and
the nanosecond-timestamp variants); it rejects pcapng (`0x0a0d0d0a`) with a
clear `cf_log` error and returns -1, and requires `DLT_EN10MB` (Ethernet)
link-layer framing.

### Manual veth capture test (rx-ring + BPF filter)

The rx-ring path (`rx_reader_start`/`rx_reader_stop`) needs `CAP_NET_RAW`
(and, for the `SCHED_FIFO` attempt, ideally `CAP_SYS_NICE` -- its absence is
logged as a warning and capture continues at normal priority) and a real
`AF_PACKET`-capable interface, so it cannot run as a CUnit test in ordinary
CI. Verify it manually with a veth pair and `scapy`, using the hidden
`rx-smoke` build target (`tests/rx_smoke_main.c`): a 20-ish-line harness that
runs `rx_reader` against a given interface for N seconds, then prints every
queued packet plus the final stats snapshot.

```sh
# 1. Build the smoke harness (not part of `all`/`test`).
make -C sources/cloudflow-source-dhcp rx-smoke

# 2. Create a veth pair: cfveth0 in the root namespace, cfveth1 in a new
#    namespace `cfns`, cabled to each other.
sudo ip netns add cfns
sudo ip link add cfveth0 type veth peer name cfveth1 netns cfns
sudo ip link set cfveth0 up
sudo ip netns exec cfns ip link set cfveth1 up
sudo ip netns exec cfns ip link set lo up
sudo ip addr add 10.200.0.1/24 dev cfveth0
sudo ip netns exec cfns ip addr add 10.200.0.2/24 dev cfveth1

# 3. Start the harness on cfveth0 (root namespace), capturing for 6s.
sudo ./sources/cloudflow-source-dhcp/build/rx-smoke cfveth0 6 &

# 4. From the other namespace, send one DHCPv4 DISCOVER and one
#    unrelated UDP packet with scapy (run as root; needs the `scapy`
#    Python package).
sudo ip netns exec cfns python3 - <<'PY'
from scapy.all import BOOTP, DHCP, Ether, IP, Raw, UDP, sendp

dhcp = (Ether(src="02:00:00:00:00:02", dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=bytes.fromhex("020000000002") + b"\x00" * 10, xid=1)
        / DHCP(options=[("message-type", "discover"), "end"]))
non_dhcp = (Ether(src="02:00:00:00:00:02", dst="ff:ff:ff:ff:ff:ff")
            / IP(src="10.200.0.2", dst="10.200.0.1")
            / UDP(sport=9999, dport=9999)
            / Raw(b"not-dhcp"))
sendp(dhcp, iface="cfveth1")
sendp(non_dhcp, iface="cfveth1")
PY

# 5. Confirm the harness printed exactly one packet (the DHCP DISCOVER)
#    and that packets_received_total == 1 -- the kernel-side BPF filter
#    dropped the non-DHCP packet before it ever reached the ring, so it
#    never even increments packets_received_total.
wait

# 6. Clean up.
sudo ip netns del cfns
```

This procedure (including the VLAN-tagged and DHCPv6 variants, and a
non-first IPv4 fragment to confirm fragment rejection) was run against this
implementation in a root container with `CAP_NET_RAW`; see the WP-08 PR
description / task report for the observed results. A single-VLAN-tagged
DHCPv4 frame and a single-VLAN-tagged non-DHCP frame are useful additions to
step 4 above: they exercise the part of the filter the earlier
DHCP-collector prototype filter got wrong (it read a fixed
byte offset that assumed no VLAN tag even in its own "VLAN-aware" branch).
