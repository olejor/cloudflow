.PHONY: proto test bench local-redis build clean

# Library/app directories with their own Makefile (each including
# mk/toolchain.mk). Extended by later WPs as libs/apps land.
SUBDIRS := libs/cloudflow-core

proto:
	./scripts/generate-protobuf.sh

# test builds and runs all unit test binaries; today that is delegated to
# scripts/run-integration-tests.sh. Per-WP unit tests (tests/unit/) get
# wired into that script as they land.
test:
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
