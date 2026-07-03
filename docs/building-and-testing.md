# Building and testing

## Toolchain (`mk/toolchain.mk`)

Every C library and app Makefile includes `mk/toolchain.mk`, which is the
single definition of the compiler flags used everywhere:

```text
C11, -Wall -Wextra -Werror -O2 -std=gnu11 -D_FORTIFY_SOURCE=2
-fstack-protector-strong -fPIE, hardened link flags -z relro -z now -z noexecstack
```

`-march=native` is deliberately never used — it would pin binaries to the
build host. Sub-Makefiles extend `CPPFLAGS` (include paths, `-D` defines)
rather than overriding `CFLAGS`, so every target keeps the same
warning/hardening baseline. Libraries build as static archives
(`libcloudflow-core.a`, etc.); apps and sinks link them.

## The top-level `Makefile`

`SUBDIRS` lists every library and app directory
(`libs/cloudflow-{core,codec,packet,redis}`,
`sources/cloudflow-source-dhcp`, `sinks/cloudflow-sink-splunk`,
`tests/unit`), each with its own Makefile built on `mk/toolchain.mk`.

```text
make build        walks SUBDIRS and builds each with `make all`
make clean        walks SUBDIRS and cleans each
make proto        runs scripts/generate-protobuf.sh
make test         builds/runs tests/unit, cloudflow-redis's live-Redis test,
                   the DHCP source's tests, the Splunk sink's tests, then
                   scripts/run-integration-tests.sh
make test-tsan     tests/unit's cf_queue stress test under -fsanitize=thread
make test-asan     ASan/UBSan build of tests/unit, the source's formatter
                   suite, and the sink's suites
make bench         scripts/benchmark-xadd.sh
make local-redis   scripts/run-local-redis.sh (standalone redis:7 container)
```

`make test` is the same entry point CI uses. `test-tsan` and `test-asan` are
kept separate from the default `test` target because sanitizer builds are
slow and are not part of the default clean-build loop.

## Protobuf codegen (`scripts/generate-protobuf.sh`, `libs/cloudflow-codec/`)

`scripts/generate-protobuf.sh` regenerates every language binding from
`proto/cloudflow/v1/*.proto`:

- C: `protoc --c_out=...` via `protoc-gen-c`/`protobuf-c`, producing
  `libs/cloudflow-codec/gen/cloudflow/v1/{common,envelope,dhcp}.pb-c.{c,h}`,
  built into `libcloudflow-codec.a`.
- Python: the same messages generated into
  `sinks/cloudflow-sink-splunk/src/cloudflow_pb/`, used by the debug tools
  and the golden-file generator (the sink binary itself is C and does not
  use these bindings at runtime).

Generated code is **committed** so ordinary builds and CI never need
`protoc` installed (D2, `docs/architecture.md`) — `scripts/generate-protobuf.sh`
is only run when a `.proto` file changes. Generated files carry a
`# GENERATED — do not edit` marker. `make proto` is idempotent: running it
twice produces an empty `git diff`, and CI's `proto-drift` job enforces
exactly that on every PR (see below).

## Test strategy

- **CUnit unit suites.** `tests/unit/` holds cross-library suites
  (`cf_queue_test.c`, `cf_event_id_test.c`, `cf_sha256_test.c`,
  `cf_time_test.c`, `cf_log_test.c`, `cf_decap_test.c`, `cf_dhcpv4_test.c`,
  `cf_dhcpv6_test.c`, `cf_codec_test.c`); each library/app also carries its
  own suite next to its source (e.g.
  `sources/cloudflow-source-dhcp/tests/rx_reader_test.c`,
  `formatter_test.c`; `sinks/cloudflow-sink-splunk/tests/test_consumer.c`,
  `test_hec.c`, `test_transform_golden.c`). Parser and codec suites are
  fixture-driven against `tests/fixtures/dhcp/` (see `docs/dhcp-source.md`).
  `libs/cloudflow-redis/tests/cf_redis_producer_test.c` spawns a private
  `redis-server` and skips cleanly if the binary is absent.
- **Integration script.** `scripts/run-integration-tests.sh` starts Redis (or
  reuses `CF_TEST_REDIS`), replays every DHCP fixture through the real
  `cloudflow-source-dhcp --replay` binary, asserts per-stream `XLEN` against
  a committed manifest, runs the sink with `--once --stdout` and diffs
  against golden JSON (ignoring the one non-deterministic envelope field,
  `ingest_time_unix_nano`), asserts zero pending entries and an empty
  dead-letter stream on a clean run, and separately proves the poison path:
  a hand-`XADD`ed garbage payload is run through the sink and must land in
  the dead-letter stream with `reason=decode_error` (see
  `docs/failure-modes.md`).
- **Fuzzing.** `tests/fuzz/` holds AFL-style harnesses for the decap layer
  (`decap_fuzz.c`) and both DHCP parsers (`dhcpv4_fuzz.c`,
  `dhcpv6_fuzz.c`), plus quick-check shell scripts. These build but are not
  required to run in CI; a local fuzzing pass is expected before merging
  parser changes.
- **Sanitizers.** `make test-tsan` runs the `cf_queue` SPSC stress test
  under ThreadSanitizer — it is the only concurrency primitive in the
  source pipeline, so it gets this treatment specifically. `make test-asan`
  runs the unit suites, the source's formatter suite, and the sink's
  suites (golden + consumer tests) under ASan/UBSan; parser and
  fuzz-adjacent code is expected to stay sanitizer-clean.

## CI (`.github/workflows/ci.yml`)

Five jobs, all on `ubuntu-latest`:

- **`build-test`** — installs the documented apt/pip dependencies, runs
  `make build` then `make test`, uploads logs on failure.
- **`proto-drift`** — re-runs `scripts/generate-protobuf.sh` and fails if
  `git status --porcelain` is non-empty, protecting the committed generated
  code.
- **`sanitizers`** — runs `make test-tsan` and `make test-asan`.
- **`python-tests`** — a `python -m compileall` syntax gate over the sink
  and `tools/`, then discovers and runs `pytest` for every `tools/*/tests/`
  directory that actually contains `test_*.py` files (the sink itself is C
  and carries no pytest suite as of the C rewrite).
- **`integration`** — runs against a `redis:7` service container,
  `CF_TEST_REDIS` pointed at it, and runs `scripts/run-integration-tests.sh`.

## Benchmark (`tests/performance/`)

`tests/performance/bench_xadd.c` links `cloudflow-redis` + `cloudflow-core`
directly: a generator thread fills a queue with synthetic `cf_event_item_t`s
(configurable payload size, default 2 KiB) and the real producer drains it
against a local Redis for a fixed duration (default 10 s), reporting
events/sec, MB/sec, average XADD latency, and final `events_lost_total`
(expected 0). `scripts/benchmark-xadd.sh` runs the binary across a matrix of
payload sizes (512/2048/8192 bytes) and pipeline sizes (1/64/512), printing
a small table; results are recorded in `tests/performance/BASELINE.md` with
the hardware and Redis version noted, so regressions are visible over time.

## Debug tools (`tools/`)

Both tools are Python (D1) console scripts that share the generated
protobuf bindings and, for the HEC mapping, the sink's own transform logic
— nothing about the mapping is duplicated.

- **`decode-event`** (`cloudflow-decode-event`) — decodes a packed
  `CloudFlowEvent` fetched from a Redis stream (`--stream <name> --id
  <entry-id>` or `--last N`), from a file, or from stdin, and pretty-prints
  it as JSON using the same field-preserving mapping as the sink. `--hec`
  prints the full canonical HEC mapping (`docs/splunk-output.md`) instead.
  Exits nonzero on decode failure, printing the protobuf error and a hex
  dump of the first 64 bytes.
- **`stream-inspect`** (`cloudflow-stream-inspect`) — reports on the
  configured streams (both wire streams plus the dead-letter stream by
  default): length and first/last entry id/time (`XINFO STREAM`), pending
  count and lag per consumer group (`XINFO GROUPS`), and per-consumer idle
  time. `--watch` refreshes a compact report every 2 seconds. `--pending
  <group>` lists individual pending entries with idle time and delivery
  count (`XPENDING` detail) — the tool to reach for when the sink looks
  stuck.

Both resolve the Redis endpoint from `--redis host:port`,
`CF_REDIS_ENDPOINTS`, or `configs/examples/redis.yaml`, in that order.
