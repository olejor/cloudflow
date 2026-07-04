#!/usr/bin/env bash
# WP-14 -- end-to-end integration test.
#
# One command: start Redis, replay every committed DHCP fixture pcap through
# the real cloudflow-source-dhcp binary, consume with the real
# cloudflow-sink-splunk binary, and assert the results. This is the same
# entry point CI's `integration` job calls and that `make test` calls last.
#
# Environment availability note (per the WP-14 task): Docker may not be
# present in every environment this runs in. `scripts/run-local-redis.sh`
# still offers the docker path for interactive dev, but this script always
# spawns a *private* `redis-server` process directly (fork/exec pattern
# lifted from libs/cloudflow-redis/tests and the sink's own
# tests/test_consumer.c) unless CF_TEST_REDIS is set -- that needs no Docker
# and cannot collide with a developer's local Redis.
#
# Bare-machine `make test` safety: if redis-server is not on PATH and
# CF_TEST_REDIS is not set, this prints a clear SKIP and exits 0 (matching
# the convention already used by libs/cloudflow-redis's and the sink's own
# private-redis test suites, which skip the same way). Once a Redis is
# available, missing binaries are built via `make build`; if they are still
# missing after that, the script fails loudly rather than skipping.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INTEGRATION_DIR="$REPO_ROOT/tests/integration"
FIXTURES_DIR="$REPO_ROOT/tests/fixtures/dhcp"
DNS_FIXTURES_DIR="$REPO_ROOT/tests/fixtures/dns"
MANIFEST="$INTEGRATION_DIR/expected_counts.tsv"
REDIS_PROBE="$INTEGRATION_DIR/redis_probe.py"
CHECK_HEC_LINES="$INTEGRATION_DIR/check_hec_lines.py"
CHECK_DNS_HEC="$INTEGRATION_DIR/check_dns_hec.py"

SOURCE_BIN="$REPO_ROOT/sources/cloudflow-source-dhcp/build/cloudflow-source-dhcp"
DNS_SOURCE_BIN="$REPO_ROOT/sources/cloudflow-source-dns/build/cloudflow-source-dns"
SINK_BIN="$REPO_ROOT/sinks/cloudflow-sink-splunk/build/cloudflow-sink-splunk"

STREAM_V4="cloudflow:v1:wire:dhcpv4"
STREAM_V6="cloudflow:v1:wire:dhcpv6"
STREAM_DNS="cloudflow:v1:wire:dns"
DEADLETTER_STREAM="cloudflow:v1:deadletter:sink-splunk"
CONSUMER_GROUP="sink-splunk"

log() { echo "[integration] $*"; }
fail() { echo "[integration] FAIL: $*" >&2; exit 1; }

REDIS_PID=""
WORKDIR=""

cleanup() {
    local status=$?
    if [[ -n "$REDIS_PID" ]] && kill -0 "$REDIS_PID" 2>/dev/null; then
        log "stopping private redis-server (pid $REDIS_PID)"
        kill "$REDIS_PID" 2>/dev/null || true
        wait "$REDIS_PID" 2>/dev/null || true
    fi
    if [[ -n "$WORKDIR" && -d "$WORKDIR" ]]; then
        rm -rf "$WORKDIR"
    fi
    exit "$status"
}
trap cleanup EXIT INT TERM

PY="$(command -v python3 || true)"

# ---- 0. availability gate: skip cleanly on a bare machine ---------------
if [[ -z "${CF_TEST_REDIS:-}" ]] && ! command -v redis-server >/dev/null 2>&1; then
    log "SKIP: redis-server not found on PATH and CF_TEST_REDIS not set;" \
        "skipping integration tests so 'make test' stays green on a bare machine."
    exit 0
fi

if [[ -z "$PY" ]]; then
    fail "python3 not found on PATH (required by the integration test helpers)"
fi

binaries_present() {
    [[ -x "$SOURCE_BIN" && -x "$DNS_SOURCE_BIN" && -x "$SINK_BIN" ]]
}

if ! binaries_present; then
    log "binaries not found ($SOURCE_BIN, $DNS_SOURCE_BIN, $SINK_BIN); running 'make build'..."
    if ! (cd "$REPO_ROOT" && make build); then
        fail "'make build' failed"
    fi
fi
binaries_present || fail "required binaries still missing after 'make build': one of $SOURCE_BIN, $DNS_SOURCE_BIN, $SINK_BIN"

[[ -f "$MANIFEST" ]] || fail "missing manifest $MANIFEST"
[[ -f "$REDIS_PROBE" ]] || fail "missing helper $REDIS_PROBE"
[[ -f "$CHECK_HEC_LINES" ]] || fail "missing helper $CHECK_HEC_LINES"
[[ -f "$CHECK_DNS_HEC" ]] || fail "missing helper $CHECK_DNS_HEC"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/cloudflow-itest.XXXXXX")"
log "workdir: $WORKDIR"

# ---- 1. start Redis (or reuse CF_TEST_REDIS) ----------------------------
if [[ -n "${CF_TEST_REDIS:-}" ]]; then
    log "using CF_TEST_REDIS=$CF_TEST_REDIS"
    REDIS_HOST="${CF_TEST_REDIS%%:*}"
    REDIS_PORT="${CF_TEST_REDIS##*:}"
else
    REDIS_HOST="127.0.0.1"
    REDIS_PORT="$("$PY" -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()')"
    log "starting private redis-server on $REDIS_HOST:$REDIS_PORT"
    redis-server --port "$REDIS_PORT" --bind "$REDIS_HOST" --save '' --appendonly no \
        >"$WORKDIR/redis-server.log" 2>&1 &
    REDIS_PID=$!

    ready=0
    for _ in $(seq 1 100); do
        if kill -0 "$REDIS_PID" 2>/dev/null && \
           "$PY" "$REDIS_PROBE" --host "$REDIS_HOST" --port "$REDIS_PORT" ping >/dev/null 2>&1; then
            ready=1
            break
        fi
        sleep 0.1
    done
    if [[ "$ready" -ne 1 ]]; then
        cat "$WORKDIR/redis-server.log" >&2 || true
        fail "private redis-server did not become ready on $REDIS_HOST:$REDIS_PORT"
    fi
    log "redis-server ready (pid $REDIS_PID)"
fi

probe() { "$PY" "$REDIS_PROBE" --host "$REDIS_HOST" --port "$REDIS_PORT" "$@"; }

# ---- 2. flush the CloudFlow streams --------------------------------------
log "flushing CloudFlow streams"
probe del "$STREAM_V4" "$STREAM_V6" "$STREAM_DNS" "$DEADLETTER_STREAM" >/dev/null

# ---- 3. run the source --replay over every fixture pcap ------------------
# Fixed source_host/capture_interface (independent of the machine running
# this script) so event_id (D5: sha256 of source_host, capture_interface,
# observed_time_unix_nano, raw frame bytes) is deterministic across runs.
SOURCE_CFG="$WORKDIR/dhcp-source.itest.yaml"
cat >"$SOURCE_CFG" <<EOF
service:
  name: cloudflow-source-dhcp
  source_host: itest-dhcp-source-01

capture:
  interface: itest0
  method: rxring
  snaplen: 1500
  filter: "udp and (port 67 or port 68 or port 546 or port 547)"

queues:
  rx_to_formatter_capacity: 65536
  formatter_to_redis_capacity: 65536
  on_full: drop_newest

redis:
  endpoints:
    - ${REDIS_HOST}:${REDIS_PORT}
  stream_dhcpv4: ${STREAM_V4}
  stream_dhcpv6: ${STREAM_V6}
  maxlen_approx: 1000000
  xadd_batch_size: 100
  xadd_flush_interval_ms: 10
EOF

mapfile -t PCAPS < <(find "$FIXTURES_DIR" -maxdepth 1 -name '*.pcap' | sort)
[[ ${#PCAPS[@]} -gt 0 ]] || fail "no fixture pcaps found under $FIXTURES_DIR"
log "replaying ${#PCAPS[@]} fixture pcaps through $SOURCE_BIN"
for pcap in "${PCAPS[@]}"; do
    name="$(basename "$pcap")"
    if ! "$SOURCE_BIN" -c "$SOURCE_CFG" --replay "$pcap" >"$WORKDIR/replay.$name.log" 2>&1; then
        cat "$WORKDIR/replay.$name.log" >&2
        fail "source --replay failed for $pcap"
    fi
done
log "replay complete"

# ---- 4. assert per-stream XLEN against the committed manifest -----------
declare -A EXPECTED_COUNTS
while IFS=$'\t' read -r stream count; do
    [[ -z "$stream" || "$stream" == \#* ]] && continue
    EXPECTED_COUNTS["$stream"]="$count"
done <"$MANIFEST"

[[ -n "${EXPECTED_COUNTS[$STREAM_V4]:-}" ]] || fail "manifest has no entry for $STREAM_V4"
[[ -n "${EXPECTED_COUNTS[$STREAM_V6]:-}" ]] || fail "manifest has no entry for $STREAM_V6"

total_expected=0
for stream in "${!EXPECTED_COUNTS[@]}"; do
    expected="${EXPECTED_COUNTS[$stream]}"
    actual="$(probe xlen "$stream")"
    log "XLEN $stream = $actual (expected $expected)"
    [[ "$actual" == "$expected" ]] || fail "XLEN mismatch for $stream: got $actual, expected $expected"
    total_expected=$((total_expected + expected))
done

V4_COUNT="${EXPECTED_COUNTS[$STREAM_V4]}"
V6_COUNT="${EXPECTED_COUNTS[$STREAM_V6]}"

# ---- 5. run the sink --once --stdout and validate the HEC lines ---------
SINK_CFG="$WORKDIR/splunk-sink.itest.yaml"
cat >"$SINK_CFG" <<EOF
service:
  name: cloudflow-sink-splunk
  consumer_name: itest-splunk-01

redis:
  endpoints:
    - ${REDIS_HOST}:${REDIS_PORT}
  streams:
    - ${STREAM_V4}
    - ${STREAM_V6}
  consumer_group: ${CONSUMER_GROUP}
  read_count: 200
  block_ms: 200

splunk:
  hec_url: http://127.0.0.1:9/services/collector/event
  hec_token_env: CF_ITEST_HEC_TOKEN
  index: ""
  sourcetypes:
    dhcpv4: cloudflow:dhcpv4
    dhcpv6: cloudflow:dhcpv6
  batch_size: 500
  flush_interval_ms: 200
  request_timeout_ms: 2000
  tls_verify: true
  include_raw_payload: false
EOF

export CF_ITEST_HEC_TOKEN="itest-dummy-hec-token"

HEC_OUT="$WORKDIR/hec_lines.jsonl"
log "running sink --once --stdout"
if ! "$SINK_BIN" -c "$SINK_CFG" --once --stdout >"$HEC_OUT" 2>"$WORKDIR/sink-run1.log"; then
    cat "$WORKDIR/sink-run1.log" >&2
    fail "sink --once --stdout failed"
fi

log "validating HEC lines (expect $total_expected: $V4_COUNT dhcpv4 + $V6_COUNT dhcpv6)"
if ! "$PY" "$CHECK_HEC_LINES" "$HEC_OUT" --dhcpv4-count "$V4_COUNT" --dhcpv6-count "$V6_COUNT"; then
    fail "HEC line validation failed (see above)"
fi

# ---- 6. assert 0 pending and an empty dead-letter stream -----------------
for stream in "$STREAM_V4" "$STREAM_V6"; do
    pending="$(probe pending "$stream" "$CONSUMER_GROUP")"
    log "pending($stream, $CONSUMER_GROUP) = $pending"
    [[ "$pending" == "0" ]] || fail "$stream group $CONSUMER_GROUP has $pending pending entries, expected 0"
done

dl_len="$(probe xlen "$DEADLETTER_STREAM")"
log "XLEN $DEADLETTER_STREAM = $dl_len (expected 0)"
[[ "$dl_len" == "0" ]] || fail "dead-letter stream not empty after a clean run: $dl_len entries"

# ---- 7. poison-path case -------------------------------------------------
log "poison-path: injecting one garbage-payload entry into $STREAM_V4"
probe xadd-poison "$STREAM_V4" >/dev/null

log "running sink --once --stdout again (poison entry)"
if ! "$SINK_BIN" -c "$SINK_CFG" --once --stdout >"$WORKDIR/poison-hec.jsonl" 2>"$WORKDIR/sink-run2.log"; then
    cat "$WORKDIR/sink-run2.log" >&2
    fail "sink --once --stdout failed on the poison-path run"
fi

if ! probe deadletter-check "$DEADLETTER_STREAM" decode_error "$STREAM_V4"; then
    fail "dead-letter validation failed for the poison entry"
fi
log "dead-letter check OK (reason=decode_error, origin_stream=$STREAM_V4)"

for stream in "$STREAM_V4" "$STREAM_V6"; do
    pending="$(probe pending "$stream" "$CONSUMER_GROUP")"
    log "pending($stream, $CONSUMER_GROUP) after poison run = $pending"
    [[ "$pending" == "0" ]] || fail "$stream group $CONSUMER_GROUP has $pending pending entries after the poison run"
done

# ---- 8. DNS leg (M-DNS1): source-dns --replay -> wire:dns -> sink --------
# End-to-end DNS: replay the committed q_a query+response pcap PAIR through
# cloudflow-source-dns so the correlation stage matches them into exactly one
# dns.transaction.observed on cloudflow:v1:wire:dns, then run the sink over
# that stream and assert the canonical cloudflow:dns HEC event.
#
# The source's --replay flag takes ONE pcap and each invocation is an
# independent process with its own pending-query correlation table, so the
# query and its response MUST arrive in the same run to correlate. Both
# fixtures are classic pcaps with an identical 24-byte global header, so we
# concatenate them (query records first, then the response's records after its
# global header) into a single replay input.
log "DNS leg: correlating the q_a query+response pair on $STREAM_DNS"
DNS_QUERY_PCAP="$DNS_FIXTURES_DIR/q_a_query.pcap"
DNS_RESPONSE_PCAP="$DNS_FIXTURES_DIR/q_a_response.pcap"
[[ -f "$DNS_QUERY_PCAP" && -f "$DNS_RESPONSE_PCAP" ]] || \
    fail "missing DNS fixture pair under $DNS_FIXTURES_DIR"

DNS_PAIR_PCAP="$WORKDIR/q_a_pair.pcap"
"$PY" - "$DNS_QUERY_PCAP" "$DNS_RESPONSE_PCAP" "$DNS_PAIR_PCAP" <<'PY'
import sys
q = open(sys.argv[1], "rb").read()
r = open(sys.argv[2], "rb").read()
if q[:24] != r[:24]:
    sys.exit("DNS fixture pcaps have differing global headers; cannot concatenate")
open(sys.argv[3], "wb").write(q + r[24:])  # keep one global header, both records
PY

probe del "$STREAM_DNS" >/dev/null
dns_dl_before="$(probe xlen "$DEADLETTER_STREAM")"

# local_service_addresses lists the DNS service IP the fixtures target (the
# 192.0.2.53 server owns port 53), so the transaction classifies CLIENT_FACING.
DNS_SOURCE_CFG="$WORKDIR/dns-source.itest.yaml"
cat >"$DNS_SOURCE_CFG" <<EOF
service:
  name: cloudflow-source-dns
  source_host: itest-dns-source-01

capture:
  interface: itest0
  method: rxring
  snaplen: 1500

queues:
  rx_to_stage_capacity: 65536
  stage_to_redis_capacity: 65536
  on_full: drop_newest

redis:
  endpoints:
    - ${REDIS_HOST}:${REDIS_PORT}
  stream_dns: ${STREAM_DNS}
  maxlen_approx: 1000000
  xadd_batch_size: 100
  xadd_flush_interval_ms: 10

dns:
  local_service_addresses:
    - 192.0.2.53
  emit_policy: all
EOF

log "replaying the concatenated DNS pcap pair through $DNS_SOURCE_BIN"
if ! "$DNS_SOURCE_BIN" -c "$DNS_SOURCE_CFG" --replay "$DNS_PAIR_PCAP" \
        >"$WORKDIR/dns-replay.log" 2>&1; then
    cat "$WORKDIR/dns-replay.log" >&2
    fail "cloudflow-source-dns --replay failed for the DNS pair"
fi

dns_xlen="$(probe xlen "$STREAM_DNS")"
log "XLEN $STREAM_DNS = $dns_xlen (expected 1)"
[[ "$dns_xlen" == "1" ]] || fail "expected exactly 1 correlated DNS transaction on $STREAM_DNS, got $dns_xlen"

DNS_SINK_CFG="$WORKDIR/splunk-sink-dns.itest.yaml"
cat >"$DNS_SINK_CFG" <<EOF
service:
  name: cloudflow-sink-splunk
  consumer_name: itest-splunk-dns-01

redis:
  endpoints:
    - ${REDIS_HOST}:${REDIS_PORT}
  streams:
    - ${STREAM_DNS}
  consumer_group: ${CONSUMER_GROUP}
  read_count: 200
  block_ms: 200

splunk:
  hec_url: http://127.0.0.1:9/services/collector/event
  hec_token_env: CF_ITEST_HEC_TOKEN
  index: ""
  sourcetypes:
    dns: cloudflow:dns
  batch_size: 500
  flush_interval_ms: 200
  request_timeout_ms: 2000
  tls_verify: true
  include_raw_payload: false
EOF

DNS_HEC_OUT="$WORKDIR/dns_hec_lines.jsonl"
log "running sink --once --stdout over $STREAM_DNS"
if ! "$SINK_BIN" -c "$DNS_SINK_CFG" --once --stdout \
        >"$DNS_HEC_OUT" 2>"$WORKDIR/dns-sink.log"; then
    cat "$WORKDIR/dns-sink.log" >&2
    fail "sink --once --stdout failed on the DNS stream"
fi

log "emitted DNS HEC event:"
cat "$DNS_HEC_OUT"
if ! "$PY" "$CHECK_DNS_HEC" "$DNS_HEC_OUT" --count 1; then
    fail "DNS HEC line validation failed (see above)"
fi

dns_pending="$(probe pending "$STREAM_DNS" "$CONSUMER_GROUP")"
log "pending($STREAM_DNS, $CONSUMER_GROUP) = $dns_pending"
[[ "$dns_pending" == "0" ]] || fail "$STREAM_DNS group $CONSUMER_GROUP has $dns_pending pending entries, expected 0"

dns_dl_after="$(probe xlen "$DEADLETTER_STREAM")"
log "dead-letter delta over DNS leg = $((dns_dl_after - dns_dl_before)) (expected 0)"
[[ "$dns_dl_after" == "$dns_dl_before" ]] || fail "DNS leg produced dead-letter entries (before=$dns_dl_before after=$dns_dl_after)"

log "PASS: ${#PCAPS[@]} fixtures replayed, XLENs matched, $total_expected HEC lines validated," \
    "0 pending, poison entry dead-lettered and acked;" \
    "DNS pair correlated into 1 cloudflow:dns event on $STREAM_DNS, 0 pending."
