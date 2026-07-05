# CloudFlow all-in-one image for the real-delivery integration harness.
#
# Builds all five app binaries and packages them with the fixtures needed for
# --replay. The docker-compose file runs each service from this one image,
# selecting the binary via `command:`.
#
# Single-stage on purpose: it keeps the build and runtime library sets
# identical, so the image is guaranteed to have every .so the binaries link
# against without pinning distro-specific runtime-package names that this
# environment cannot verify. A slimmed multi-stage variant (runtime-only libs)
# is a worthwhile follow-up once the harness is green in CI.
#
# Build context is the repo root (see docker-compose.yml `build.context`).
FROM debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libc6-dev make pkg-config \
        protobuf-compiler protobuf-c-compiler libprotobuf-c-dev \
        libhiredis-dev libyaml-dev libcurl4-openssl-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Build every library, source, and sink. `make build` is the same target CI
# and developers use, so the harness exercises the real artifacts.
RUN make build \
    && install -m 0755 \
        sources/cloudflow-source-dhcp/build/cloudflow-source-dhcp \
        sources/cloudflow-source-dns/build/cloudflow-source-dns \
        sinks/cloudflow-sink-splunk/build/cloudflow-sink-splunk \
        sinks/cloudflow-sink-splunk-metrics/build/cloudflow-sink-splunk-metrics \
        sinks/cloudflow-sink-clickhouse/build/cloudflow-sink-clickhouse \
        /usr/local/bin/

# Committed pcap fixtures, so sources can --replay deterministic input.
# (Already present under /src/tests/fixtures from the COPY above; expose them
# at a stable path the compose commands reference.)
RUN ln -s /src/tests/fixtures /fixtures

# Run unprivileged: the harness uses --replay (no AF_PACKET capture), so no
# capabilities are needed. nobody:nogroup exists in debian:12-slim.
USER nobody:nogroup
