# Foundations: build, codegen, core library, queue

Work packages WP-01 through WP-04. Read `00-overview.md` first, especially the
Decisions and Conventions sections.

---

## WP-01 — Build system and repo scaffolding

**Goal.** A top-level `make` that builds every C library and binary in the
repo with one toolchain definition, and creates the target directory layout.

**Deliverables.**

- `Makefile` (replace the current TODO stubs for `build`/`clean`): targets
  `build`, `test`, `clean`, `proto`, `local-redis`, `bench`. `build` walks the
  library and app directories; `test` builds and runs all unit test binaries.
- `mk/toolchain.mk`: single definition of `CC`, `CFLAGS`, `LDFLAGS` (flags per
  Convention 3), included by every sub-Makefile. Hardened link flags
  `-z relro -z now -z noexecstack`.
- Sub-Makefiles: `libs/cloudflow-core/Makefile`, one per library/app as those
  WPs land — this WP creates the pattern with a stub library so later WPs only
  copy it. Libraries build as static archives (`libcloudflow-core.a` etc.);
  apps link them.
- Directory scaffolding per the layout in `00-overview.md` (empty dirs with
  `.gitkeep` where needed).

**Dependencies (system).** Document in the README a single install line for
each of: gcc/clang, make, `protobuf-c` + `protoc`, `libprotobuf-c-dev`,
`hiredis-dev`, `libyaml-dev`, CUnit, Python 3.9+. Target platforms:
recent glibc Linux (the capture path is Linux-only by nature).

**Explicitly out of scope.** Autotools/CMake, packaging, Docker images.

**Acceptance criteria.**
- `make build` produces the stub static library; `make clean` removes all
  artifacts; both are idempotent.
- A deliberately introduced `-Wunused` warning fails the build (proves
  `-Werror` is live).
- `import/` is not touched by any target.

---

## WP-02 — Protobuf codegen pipeline

**Goal.** One script that regenerates all protobuf bindings; generated code is
committed so builds and CI never need `protoc`.

**Deliverables.**

- `scripts/generate-protobuf.sh` (replace the TODO stub):
  - C: `protoc --c_out=libs/cloudflow-codec/gen proto/cloudflow/v1/*.proto`
    (via `protoc-gen-c` / `protobuf-c`), producing
    `libs/cloudflow-codec/gen/cloudflow/v1/{common,envelope,dhcp}.pb-c.{c,h}`.
  - Python: `protoc --python_out=sinks/cloudflow-sink-splunk/src/cloudflow_pb`
    for the same files, plus a generated-package `__init__.py`.
  - The script pins/echoes the protoc and plugin versions it ran with, and
    fails loudly if the tools are missing.
- `libs/cloudflow-codec/Makefile` building `libcloudflow-codec.a` from the
  generated C sources (no hand-written code in this WP).
- Committed generated output for the current `.proto` files.
- A `make proto` target already exists and calls the script — verify it works.

**Rules.** Generated files carry a `# GENERATED — do not edit` marker in a
committed header comment or adjacent README. CI (WP-16) later verifies that
re-running the script produces no diff.

**Acceptance criteria.**
- `make proto` is idempotent (second run yields an empty `git diff`).
- `make build` compiles the generated C without warnings (if the generator
  output triggers warnings, suppress them for `gen/` only via per-directory
  CFLAGS, not globally).
- A trivial C test program can round-trip a `Cloudflow__V1__CloudFlowEvent`
  (pack → unpack → compare `event_id`); a trivial Python check can import the
  generated module and do the same. Both wired into `make test`.

---

## WP-03 — `cloudflow-core` library

**Goal.** Relocate the existing core code and add the small shared services
every other component needs: time, logging, stats counters, shutdown
coordination, and event IDs.

**Reuse.** Lift and rename from `import/network_syslog_collector/src/`:
`utils.c/h` (monotonic time helpers, `sleep_ns`, `ASSERT`, `likely/unlikely`),
`sync.c/h` (atomic stop flag), the `ATOMIC_INC/ADD/READ/READ_AND_ZERO` macro
pattern from `stats.h`. Move the existing `src/cloudflow.{c,h}` and
`src/cf_queue.{c,h}` into `libs/cloudflow-core/` unchanged (WP-04 hardens the
queue separately). Delete the top-level `src/` when done.

**Deliverables** (all under `libs/cloudflow-core/`):

- `cloudflow.h`, `cloudflow.c` — moved; bump `CLOUDFLOW_EVENT_MAX_SIZE` to
  8192 per D11.
- `cf_queue.h`, `cf_queue.c` — moved verbatim.
- `cf_time.h/.c`:
  ```c
  int64_t cf_now_unix_nano(void);        // CLOCK_REALTIME
  int64_t cf_now_mono_nano(void);        // CLOCK_MONOTONIC
  void    cf_sleep_ns(int64_t ns);
  ```
- `cf_sync.h/.c` — stop-flag API, lifted:
  ```c
  void cf_stop_notify(int code);
  int  cf_stop_notified(void);           // 0 = keep running
  void cf_stop_install_signal_handlers(void);   // SIGINT/SIGTERM
  ```
- `cf_log.h/.c` — structured JSON lines on stderr per Convention 7:
  ```c
  void cf_log_init(const char *service_name);
  void cf_log(cf_log_level_t level, const char *msg, /* key/value pairs */ ...);
  ```
  Keep it simple: a fixed-size line buffer, varargs of alternating
  `const char *key, const char *value` terminated by NULL, plus `_i64`/`_u64`
  helpers or a tiny kv-builder — implementer's choice, but no allocation per
  log call and the output must be valid JSON (escape control chars/quotes).
- `cf_event_id.h/.c` — D5 deterministic IDs:
  ```c
  #define CF_EVENT_ID_LEN 33   // 32 hex chars + NUL
  void cf_event_id(char out[CF_EVENT_ID_LEN],
                   const char *source_host,
                   const char *capture_interface,
                   int64_t observed_time_unix_nano,
                   const uint8_t *frame, size_t frame_len);
  ```
  Vendor a public-domain SHA-256 (single .c/.h, e.g. the classic B-Con/
  Brad Conte implementation) into `libs/cloudflow-core/sha256.{c,h}` with
  provenance noted in a comment. Hash the fields length-prefixed (not just
  concatenated) so field boundaries can't collide; truncate to 16 bytes,
  lowercase hex.
- `cf_stats.h` — the atomic counter macros (`CF_ATOMIC_INC` etc.). Each app
  defines its own stats struct; core only provides the primitives.

**Acceptance criteria.**
- Everything in the repo compiles with `src/` deleted.
- CUnit tests: event-id is stable across calls and differs when any input
  field differs (including the boundary case: `("ab","c")` vs `("a","bc")`);
  SHA-256 passes the standard NIST vectors ("abc", empty string, 448-bit
  message); log output parses as JSON (test feeds tricky strings: quotes,
  newlines, non-ASCII).

---

## WP-04 — SPSC queue hardening and tests

**Goal.** Make the existing `cf_queue` provably correct off x86 and covered by
tests. It is the only concurrency primitive in the source pipeline.

**Background.** The current `cf_queue.c` (and the legacy `queue.c` it mirrors)
uses default sequentially-consistent atomics; correctness of the payload copy
relative to head/tail publication should be made explicit with
acquire/release ordering, which is also faster.

**Deliverables.**

- `cf_queue.c` updated: producer publishes with
  `atomic_store_explicit(&q->head, ..., memory_order_release)` after the
  element `memcpy`; consumer reads head with `memory_order_acquire` before
  copying out, and symmetrically for tail. Document the ordering argument in
  comments. API in `cf_queue.h` is unchanged.
- `tests/unit/cf_queue_test.c` (CUnit, pattern from legacy
  `tests/queue_unit_test.c`): init/destroy, fill-to-capacity returns full,
  pop-empty returns empty, payload integrity round-trip, wrap-around across
  many cycles on a tiny queue, and a 2-thread stress test (producer pushes N
  sequenced elements, consumer verifies strict ordering and content, run under
  `-fsanitize=thread` in a dedicated make target `test-tsan`).

**Acceptance criteria.**
- All unit tests pass; `make test-tsan` runs the stress test clean.
- No API change (later WPs already code against `cf_queue.h`).
