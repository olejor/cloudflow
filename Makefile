.PHONY: proto test bench local-redis build clean

proto:
	./scripts/generate-protobuf.sh

test:
	./scripts/run-integration-tests.sh

bench:
	./scripts/benchmark-xadd.sh

local-redis:
	./scripts/run-local-redis.sh

build:
	@echo "TODO: build cloudflow-source-dhcp and cloudflow-sink-splunk"

clean:
	@echo "TODO: clean build artifacts"
