.PHONY: proto test bench local-redis build clean

# Library/app directories with their own Makefile (each including
# mk/toolchain.mk). Extended by later WPs as libs/apps land.
SUBDIRS := libs/cloudflow-core libs/cloudflow-codec tests/unit

proto:
	./scripts/generate-protobuf.sh

# test builds and runs all unit test binaries first, then delegates to
# scripts/run-integration-tests.sh. Per-WP unit tests (tests/unit/) are
# wired in here as they land -- WP-03 adds the first one.
test:
	$(MAKE) -C tests/unit test-unit
	./scripts/run-integration-tests.sh

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
