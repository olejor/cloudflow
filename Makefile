.PHONY: proto test test-tsan test-asan bench local-redis build clean

# Library/app directories with their own Makefile (each including
# mk/toolchain.mk). Extended by later WPs as libs/apps land.
SUBDIRS := libs/cloudflow-core libs/cloudflow-codec libs/cloudflow-packet libs/cloudflow-redis tests/unit

proto:
	./scripts/generate-protobuf.sh

# test builds and runs all unit test binaries first, then delegates to
# scripts/run-integration-tests.sh. Per-WP unit tests (tests/unit/) are
# wired in here as they land -- WP-03 adds the first one. cloudflow-redis
# keeps its live-Redis test local to its own Makefile (WP-09); it spawns a
# private redis-server and skips cleanly when the binary is absent.
test:
	$(MAKE) -C tests/unit test-unit
	$(MAKE) -C libs/cloudflow-redis test
	./scripts/run-integration-tests.sh

# WP-04: rebuilds the cf_queue SPSC stress test with -fsanitize=thread
# (queue code compiled in directly, not linked from the .a -- see
# tests/unit/Makefile) and runs it. Kept separate from `test` since TSan
# builds are slow and not part of the default CI-clean-build loop.
test-tsan:
	$(MAKE) -C tests/unit test-tsan

# WP-16: ASan+UBSan build of all four unit test binaries (core, codec,
# queue, decap -- see tests/unit/Makefile's test-asan target for why this
# one runs all suites, unlike test-tsan which only runs the queue stress
# test). Kept separate from `test` for the same reason test-tsan is: slow,
# instrumented, not part of the default CI-clean-build loop.
test-asan:
	$(MAKE) -C tests/unit test-asan

bench:
	./scripts/benchmark-xadd.sh

local-redis:
	./scripts/run-local-redis.sh

build:
	@for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir all || exit 1; \
	done

clean:
	@for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir clean || exit 1; \
	done
