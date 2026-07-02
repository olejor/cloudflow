# CloudFlow v0.1 design overview

This directory is the implementation design for the first CloudFlow deliverable:

```text
DHCPv4/DHCPv6 packet capture -> protobuf CloudFlowEvent -> Redis Streams -> Splunk
```

It breaks the system into independent **work packages (WPs)** that can each be
implemented in isolation by a separate contributor or agent. Read this file
first, then the spec that contains your WP:

| Doc | Contents |
|---|---|
| `00-overview.md` | Decisions, component map, WP index, dependency graph, milestones, implementer conventions |
| `01-foundations.md` | WP-01 build system, WP-02 protobuf codegen, WP-03 core library, WP-04 SPSC queue hardening |
| `02-packet-and-parsing.md` | WP-05 packet decap, WP-06 DHCPv4 parser, WP-07 DHCPv6 parser, fixture requirements |
| `03-source-dhcp.md` | WP-08 capture (rx-reader), WP-09 Redis producer, WP-10 event formatter, WP-11 source app |
| `04-sink-splunk.md` | WP-12 Splunk sink, canonical protobuf-to-Splunk JSON mapping |
| `05-tools-tests-ci.md` | WP-13 debug tools, WP-14 integration environment, WP-15 benchmarks, WP-16 CI |

Authoritative background documents (already in the repo, do not contradict them):
`README.md`, `AGENTS.md`, `docs/architecture.md`, `docs/event-model.md`,
`docs/redis-streams.md`, `docs/splunk-output.md`, `docs/failure-modes.md`, and
the protobuf contract under `proto/cloudflow/v1/`.

## Prior art in `import/`

Two legacy codebases were imported as reference material. They are **read-only
inputs**: lift code out of them into the new tree, never build against them or
modify them.

- `import/network_syslog_collector/` is the architectural reference. It is a
  working production collector with the exact pipeline shape we want:
  TPACKET_V3 mmap RX ring with epoll (`src/rx-ring.c`), bounded SPSC queues
  (`src/queue.c`), pipelined `XADD` with reconnect/backoff (`src/redis.c`),
  atomic stats (`src/stats.c`), env+getopt config (`src/config.c`), stop-flag
  shutdown (`src/sync.c`), time helpers (`src/utils.c`), CUnit + AFL test
  scaffolding (`tests/`), and a docker-compose Redis environment (`docker/`).
- `import/network_dhcp_collector/` is a set of prototypes. Only three things
  in it are worth lifting: the DHCPv4/DHCPv6 parsing logic
  (`process_dhcpv4`/`process_dhcpv6` in `src/main.c`, richer variants in
  `src/test.c`), the VLAN-aware DHCP cBPF filter bytecode (`src/main.c`), and
  the pcap replay reader (`src/replay.c`). Its `Makefile` is broken, its
  `README.md` describes a different project, and its `src/ring.c` iterates the
  TPACKET_V3 ring incorrectly (per-frame walk instead of block walk). **Do not
  copy `ring.c`'s ring loop** — use the syslog collector's `block_walk`.

Each WP spec names the exact legacy files/functions to lift or adapt.

## Decisions

Numbered so specs and PRs can reference them. If an implementer needs to
deviate, the deviation must be called out in the PR description and these docs
updated.

- **D1 — Languages.** The DHCP source and all shared hot-path libraries are
  C11 (matches `src/`, the proven legacy code, and the low-allocation
  requirement). The Splunk sink and debug tools are Python 3.9+: they are
  I/O-bound, not hot-path, and the protobuf/HTTP/JSON work is dramatically
  easier to implement correctly. A compiled rewrite of the sink stays possible
  later because the Redis entry format is the contract, not the code.
- **D2 — Protobuf runtime.** `protobuf-c` for C (the schema uses strings and
  repeated nested messages heavily; nanopb would fight it), standard
  `protobuf` for Python. Generated code is committed (see WP-02) so builds
  do not require protoc.
- **D3 — Redis client.** v0.1 targets a **standalone** Redis using `hiredis`
  with pipelined `XADD`. The legacy collector used `hiredis-cluster`, but a
  Redis Stream is a single key: two streams gain almost nothing from cluster
  mode, and standalone keeps the local dev loop trivial (`make local-redis`).
  The config keeps a list of endpoints; v0.1 uses the first and fails over to
  the next on connect failure. Cluster support is a possible later WP.
- **D4 — Thread model.** Exactly three threads in the source, joined by two
  bounded SPSC `cf_queue` queues, as `AGENTS.md` prescribes:
  `rx-reader -> [cf_packet_item_t] -> event-formatter -> [cf_event_item_t] -> redis-producer`.
  The item structs already exist in `src/cloudflow.h`.
- **D5 — Event identity.** `event_id` is deterministic: the lowercase-hex,
  128-bit truncation of SHA-256 over
  `(source_host, capture_interface, observed_time_unix_nano, raw frame bytes)`.
  Replaying the same capture yields the same IDs, which is what makes
  downstream duplicate handling possible (AGENTS.md principle 7).
- **D6 — Configuration.** YAML files (the examples in `configs/examples/` are
  the schema), loaded with `libyaml`, with environment-variable overrides for
  endpoints and secrets. Secrets (Splunk HEC token) are env-only, never in
  YAML.
- **D7 — Capture.** `AF_PACKET` + `PACKET_RX_RING` with **TPACKET_V3** block
  ring and epoll, lifted from the syslog collector. A fixed, VLAN-aware cBPF
  program filters UDP ports 67/68/546/547 in-kernel. The `capture.filter`
  string in the config is informational only in v0.1 (logged with a warning if
  it differs from the builtin).
- **D8 — Metrics.** Atomic counters (lift the `ATOMIC_*` macro pattern from
  the legacy `stats.h`), reported as one structured JSON log line per stats
  interval, using the metric names in `AGENTS.md`. No Prometheus endpoint in
  v0.1.
- **D9 — Backpressure.** Every queue has an explicit `on_full` policy from
  config: `drop_newest` (default), `drop_oldest`, or `block`. Every drop
  increments a counter that appears in the stats line. No hidden buffering.
- **D10 — Parse placement.** The rx-reader does no parsing: it copies the
  frame plus ring timestamp into the packet queue and returns the block to the
  kernel. All DHCP parsing and protobuf building happens in the
  event-formatter thread. DHCP is a low-rate protocol even on large networks,
  so the formatter may allocate per event; the rx thread may not allocate at
  all in steady state.
- **D11 — Event size.** Raise `CLOUDFLOW_EVENT_MAX_SIZE` to 8192: a fully
  populated `DhcpV4PacketEvent` carries the raw payload plus every option
  value twice (raw_options + decoded) and can exceed 4096. If an encoded
  event still exceeds the cap, the formatter drops `raw_dhcp_payload`, sets
  `raw_payload_truncated = true`, and re-encodes; if it still does not fit,
  the event is dropped with a counter.

## Target repository layout

New code lands here (matches the layout promised in `README.md`):

```text
libs/cloudflow-core/      WP-03, WP-04  (absorbs today's src/)
libs/cloudflow-codec/     WP-02         (generated protobuf-c + helpers)
libs/cloudflow-packet/    WP-05..07     (decap + DHCP parsers)
libs/cloudflow-redis/     WP-09         (XADD producer)
sources/cloudflow-source-dhcp/src/   WP-08, WP-10, WP-11
sinks/cloudflow-sink-splunk/src/     WP-12  (Python package)
tools/decode-event/       WP-13
tools/stream-inspect/     WP-13
tests/unit/               per-WP C unit tests
tests/fixtures/dhcp/      WP-06/07 fixtures (pcaps + expected JSON)
tests/integration/        WP-14
tests/performance/        WP-15
.github/workflows/        WP-16
```

The existing `src/` directory is relocated into `libs/cloudflow-core/` by
WP-03; nothing else may depend on `src/` after that.

## Work package index and dependency graph

| WP | Title | Language | Depends on | Size |
|---|---|---|---|---|
| WP-01 | Build system + repo scaffolding | make/C | — | S |
| WP-02 | Protobuf codegen pipeline | sh/protoc | WP-01 | S |
| WP-03 | `cloudflow-core` library | C | WP-01 | M |
| WP-04 | SPSC queue hardening + tests | C | WP-03 | S |
| WP-05 | Packet decap library | C | WP-03 | M |
| WP-06 | DHCPv4 parser | C | WP-02, WP-05 | L |
| WP-07 | DHCPv6 parser | C | WP-02, WP-05 | L |
| WP-08 | rx-reader capture module | C | WP-03, WP-04 | M |
| WP-09 | Redis XADD producer library | C | WP-03, WP-04 | M |
| WP-10 | Event formatter | C | WP-06, WP-07 | M |
| WP-11 | `cloudflow-source-dhcp` app | C | WP-08, WP-09, WP-10 | M |
| WP-12 | `cloudflow-sink-splunk` app | Python | WP-02 | L |
| WP-13 | `decode-event` + `stream-inspect` tools | Python | WP-02 | S |
| WP-14 | Integration environment + tests | sh/Python | WP-11, WP-12 | M |
| WP-15 | XADD benchmark | sh/C | WP-09 | S |
| WP-16 | CI workflows | YAML | WP-01..04 | S |

```text
WP-01 ──> WP-02 ──────────────┬──> WP-06 ──┐
   │                          ├──> WP-07 ──┤
   ├──> WP-03 ──> WP-04 ──┐   │            ├──> WP-10 ──┐
   │        │             ├───┼──> WP-08 ──┼────────────┼──> WP-11 ──┐
   │        └──> WP-05 ───┘   │            │            │            ├──> WP-14
   │                          └──> WP-09 ──┴────────────┘            │
   └────────────────────────────── WP-12 ────────────────────────────┘
                                   WP-13 (after WP-02, anytime)
                                   WP-15 (after WP-09)
                                   WP-16 (after WP-04, extend as WPs land)
```

Parallelizable batches (each row can run concurrently once the previous row
merged):

1. WP-01
2. WP-02, WP-03
3. WP-04, WP-05, WP-12 (starts against committed generated Python), WP-13, WP-16
4. WP-06, WP-07, WP-08, WP-09
5. WP-10, WP-15
6. WP-11
7. WP-14

## Milestones

- **M1 — first packet end to end** (README "recommended first milestone").
  Requires WP-01..06, WP-08..11, plus WP-12 in stdout mode: replay a DHCPv4
  DISCOVER pcap through the source, `XADD` to local Redis, sink prints the
  decoded JSON to stdout.
- **M2 — DHCPv6 + full option decode.** WP-07 merged, fixtures green.
- **M3 — Splunk HEC delivery.** WP-12 complete: HEC batching, retry,
  dead-letter stream, ack-after-delivery.
- **M4 — operational hardening.** WP-14..16: integration tests in CI,
  benchmark baseline recorded, failure-mode docs updated with measured
  behavior.

## Conventions for implementers

These rules exist so many small contributions compose into one coherent
system. They apply to every WP.

1. **Scope.** One WP per branch/PR. Touch only the files your WP lists plus
   the docs it tells you to update. Do not refactor neighbouring code, do not
   "improve" other WPs' interfaces. If an interface in these specs cannot work
   as written, stop and flag it in the PR rather than silently changing it.
2. **Contracts first.** Public C APIs are specified as header signatures in
   each WP. Implement them exactly; downstream WPs are written against them.
   Protobuf field numbers are append-only per `AGENTS.md`.
3. **Toolchain.** C11, `-Wall -Wextra -Werror -O2 -std=gnu11
   -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE`. Do **not** use
   `-march=native` (the legacy Makefile does; it pins binaries to the build
   host). Python: 3.9+, standard library plus `protobuf`, `redis`, `requests`,
   `PyYAML` only.
4. **Tests are part of the WP.** Every WP lists acceptance criteria; the PR
   must include the tests that demonstrate them, wired into `make test`. C
   unit tests use CUnit (pattern: legacy `tests/queue_unit_test.c`). Parser
   WPs must be fixture-driven.
5. **Failure behavior is explicit.** Any code path that can lose an event must
   increment a named counter and be mentioned in `docs/failure-modes.md`.
6. **No secrets, no real traffic.** Fixtures use documentation address space
   (RFC 5737 IPv4, RFC 3849 IPv6) and locally-administered MACs
   (`02:xx:...`). HEC tokens come from env vars only.
7. **Structured logs.** One JSON object per line on stderr: at minimum
   `ts`, `level`, `service`, `msg`, plus context keys. No printf-style free
   text in services (tools may print human output).
8. **Definition of done.** Builds clean with the flags above; `make test`
   passes; acceptance criteria demonstrably met; docs listed in the WP
   updated; PR description states which WP it implements and any deviations
   from this design.
