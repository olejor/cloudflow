# Tools, integration tests, benchmarks, CI

Work packages WP-13 through WP-16. These make the pipeline debuggable and
keep it honest. Per `AGENTS.md`: "Debug tooling is part of the product, not an
afterthought."

---

## WP-13 — Debug tools: `decode-event` and `stream-inspect`

Python (D1), sharing the generated bindings from WP-02 and the mapping code
from WP-12 where noted. Human-facing output is fine here (Convention 7's
JSON-logs rule applies to services, not tools).

**Deliverables.**

- `tools/decode-event/` (console script `cloudflow-decode-event`):
  - Input modes: `--stream <name> [--id <entry-id> | --last N]` (fetch from
    Redis via `XRANGE`/`XREVRANGE`), `--file <path>` (raw packed
    `CloudFlowEvent` bytes, e.g. the WP-06 fixture round-trip output), or
    stdin.
  - Output: pretty-printed JSON via the same
    `MessageToDict(preserving_proto_field_name=True)` rule as WP-12 (import
    the transform helper, don't duplicate it); `--hec` flag prints the full
    WP-12 HEC mapping instead. Exit nonzero on decode failure with the
    protobuf error and a hex dump of the first 64 bytes.
- `tools/stream-inspect/` (console script `cloudflow-stream-inspect`):
  - Default report for the configured streams (both wire streams + the
    dead-letter stream): `XINFO STREAM` (length, first/last entry id/time),
    `XINFO GROUPS` (pending count, last-delivered-id, lag), consumers with
    idle times.
  - `--watch` mode: refresh every 2 s, one compact line per stream.
  - `--pending <group>`: list pending entries with idle ms and delivery
    counts (`XPENDING` detail) — the tool you reach for when the sink is
    stuck.
- Both read the Redis endpoint from `--redis host:port`, `CF_REDIS_ENDPOINTS`,
  or `configs/examples/redis.yaml`, in that precedence order.

**Acceptance criteria.** `decode-event --file` on a fixture event matches the
WP-12 golden JSON; `stream-inspect` against the WP-14 environment shows both
streams and the `sink-splunk` group with zero pending after a clean run.
Basic pytest coverage for argument handling and decode-failure output.

---

## WP-14 — Integration environment and end-to-end tests

**Goal.** One command spins up Redis, replays fixtures through the real
source binary, consumes with the real sink, and asserts the results —
locally and in CI. This is milestone M1 automated, then extended to the full
corpus.

**Deliverables.**

- `scripts/run-local-redis.sh` — keep as is (standalone `redis:7`, D3), add
  a named container + `--stop` flag so tests can manage it.
- `scripts/run-integration-tests.sh` (replace the TODO stub):
  1. start Redis (or reuse `CF_TEST_REDIS`),
  2. flush the CloudFlow streams,
  3. run `cloudflow-source-dhcp --replay` over every fixture pcap,
  4. assert per-stream `XLEN` equals the expected event counts (committed
     manifest `tests/integration/expected_counts.tsv`),
  5. run the sink `--once --stdout`, diff against the WP-12 golden JSON
     files (ignoring `ingest_time_unix_nano`, which is the one
     non-deterministic envelope field — strip it in the diff step),
  6. assert 0 pending entries in the `sink-splunk` group and 0 entries in
     the dead-letter stream,
  7. poison-path case: XADD one garbage-payload entry, run the sink, assert
     it lands in the dead-letter stream with `reason=decode_error` and the
     group shows 0 pending.
- `tests/integration/` — the manifest, goldens, and any helper Python.
- Update `docs/failure-modes.md`: replace the open questions with the
  decided behaviors (D9 policies, WP-09 retry-once/loss accounting, WP-12
  retry/dead-letter policy) and reference the integration cases that prove
  them.

**Acceptance criteria.** `make test` green with Docker available;
the script is the same entry point CI uses; total runtime under ~2 minutes.

---

## WP-15 — XADD benchmark

**Goal.** A repeatable number for the producer path so regressions are
visible and capacity planning has a baseline. DHCP is low-rate, but the
producer library (WP-09) is shared infrastructure for future higher-rate
sources — benchmark it, not DHCP.

**Deliverables.**

- `tests/performance/bench_xadd.c` — standalone binary linking
  `cloudflow-redis` + `cloudflow-core`: fills a queue with synthetic
  `cf_event_item_t`s (configurable payload size, default 2 KiB) from a
  generator thread and runs the real producer against a local Redis for a
  fixed duration (default 10 s). Reports events/sec, MB/sec, avg XADD
  latency, and final `events_lost_total` (must be 0).
- `scripts/benchmark-xadd.sh` (replace stub): starts local Redis, runs the
  binary across payload sizes {512, 2048, 8192} and pipeline sizes {1, 64,
  512}, prints a small table.
- Record the first baseline in `tests/performance/BASELINE.md` with the
  hardware/Redis version noted.

**Acceptance criteria.** Script runs end to end locally; numbers land in
BASELINE.md; a `pipeline=1` vs `pipeline=512` delta is visible (sanity check
that pipelining is actually engaged).

---

## WP-16 — CI workflows

**Goal.** Every PR gets: build, unit tests, protobuf drift check, and (where
runner capabilities allow) integration tests.

**Deliverables** (`.github/workflows/ci.yml`):

- Job `build-test` (ubuntu-latest): install deps (WP-01's documented list),
  `make build`, `make test` (unit only if no Docker), upload test logs on
  failure.
- Job `proto-drift`: run `scripts/generate-protobuf.sh`, fail on non-empty
  `git status --porcelain` (protects committed generated code, D2).
- Job `sanitizers`: `make test-tsan` (WP-04) plus an ASan/UBSan build of the
  unit tests (`make test-asan`; add the target to `mk/toolchain.mk` — parser
  fuzz-adjacent code should always be sanitizer-clean).
- Job `integration`: services: redis:7; run
  `scripts/run-integration-tests.sh` with `CF_TEST_REDIS` pointing at the
  service. Marked `continue-on-error: false` once WP-14 lands; before that
  the job is added but gated on the script existing.
- Python: `pytest` for the sink and tools, plus `python -m compileall` as a
  cheap syntax gate.

**Acceptance criteria.** All jobs green on a no-op PR; a PR that edits a
`.proto` without regenerating fails `proto-drift`; a PR that introduces a
data race in `cf_queue` fails `sanitizers`.
