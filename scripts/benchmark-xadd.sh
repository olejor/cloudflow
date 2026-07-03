#!/usr/bin/env bash
# WP-15 -- XADD benchmark driver.
#
# Starts a private redis-server (not the shared dev instance from
# scripts/run-local-redis.sh -- a throwaway one on its own port, same spawn
# pattern as libs/cloudflow-redis/tests/cf_redis_producer_test.c: fork a
# fresh temp dir, `--save ''`, poll for readiness instead of a fixed sleep,
# trap cleanup), builds tests/performance/bench_xadd, then runs it across
# the payload x pipeline matrix and prints a small table.
#
# Invoked via the top-level `make bench` target.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PERF_DIR="$ROOT/tests/performance"
BENCH_BIN="$PERF_DIR/build/bench_xadd"

REDIS_PORT=6398
REDIS_ENDPOINT="127.0.0.1:${REDIS_PORT}"
DURATION_S=3

PAYLOAD_SIZES=(512 2048 8192)
PIPELINES=(1 64 512)

REDIS_PID=""
REDIS_TMPDIR=""

log() {
    echo "benchmark-xadd: $*" >&2
}

cleanup() {
    if [[ -n "$REDIS_PID" ]] && kill -0 "$REDIS_PID" 2>/dev/null; then
        kill "$REDIS_PID" 2>/dev/null || true
        for _ in $(seq 1 50); do
            kill -0 "$REDIS_PID" 2>/dev/null || break
            sleep 0.1
        done
        kill -0 "$REDIS_PID" 2>/dev/null && kill -9 "$REDIS_PID" 2>/dev/null || true
    fi
    if [[ -n "$REDIS_TMPDIR" && -d "$REDIS_TMPDIR" ]]; then
        rm -rf "$REDIS_TMPDIR"
    fi
}
trap cleanup EXIT

if ! command -v redis-server >/dev/null 2>&1; then
    echo "benchmark-xadd: redis-server binary not found on PATH -- install redis-server to run this benchmark" >&2
    exit 1
fi

REDIS_TMPDIR="$(mktemp -d /tmp/cf_bench_redis_XXXXXX)"
log "starting private redis-server on port ${REDIS_PORT} (cwd=${REDIS_TMPDIR})"

(
    cd "$REDIS_TMPDIR"
    exec redis-server --port "$REDIS_PORT" --save '' \
        >"$REDIS_TMPDIR/redis-server.log" 2>&1
) &
REDIS_PID=$!

redis_ready() {
    redis-cli -p "$REDIS_PORT" ping >/dev/null 2>&1
}

READY=0
for _ in $(seq 1 100); do
    if ! kill -0 "$REDIS_PID" 2>/dev/null; then
        log "redis-server exited early -- see ${REDIS_TMPDIR}/redis-server.log"
        cat "$REDIS_TMPDIR/redis-server.log" >&2 || true
        exit 1
    fi
    if redis_ready; then
        READY=1
        break
    fi
    sleep 0.1
done

if [[ "$READY" -ne 1 ]]; then
    log "redis-server did not become ready in time"
    exit 1
fi

log "redis-server ready (pid=${REDIS_PID})"

log "building bench_xadd"
make -C "$PERF_DIR" all >&2

RESULTS_FILE="$(mktemp /tmp/cf_bench_results_XXXXXX)"
trap 'rm -f "$RESULTS_FILE"; cleanup' EXIT

declare -A RESULT_EVENTS_PER_SEC
declare -A RESULT_MB_PER_SEC
declare -A RESULT_LATENCY_US
declare -A RESULT_RECONNECTS
declare -A RESULT_LOST

FAILED=0

for payload in "${PAYLOAD_SIZES[@]}"; do
    for pipeline in "${PIPELINES[@]}"; do
        log "running payload_size=${payload} pipeline=${pipeline} duration_s=${DURATION_S}"

        LINE="$("$BENCH_BIN" \
            --payload-size "$payload" \
            --pipeline "$pipeline" \
            --duration-s "$DURATION_S" \
            --redis "$REDIS_ENDPOINT" \
            2>>"$REDIS_TMPDIR/bench.log")" || {
            log "bench_xadd exited nonzero for payload_size=${payload} pipeline=${pipeline}"
            FAILED=1
            continue
        }

        echo "$LINE" >>"$RESULTS_FILE"

        key="${payload}_${pipeline}"
        events_per_sec="$(echo "$LINE" | grep -oE 'events_per_sec=[0-9.]+' | cut -d= -f2)"
        mb_per_sec="$(echo "$LINE" | grep -oE 'mb_per_sec=[0-9.]+' | cut -d= -f2)"
        latency_us="$(echo "$LINE" | grep -oE 'avg_xadd_latency_us=[0-9.]+' | cut -d= -f2)"
        reconnects="$(echo "$LINE" | grep -oE 'reconnects=[0-9]+' | cut -d= -f2)"
        lost="$(echo "$LINE" | grep -oE 'events_lost_total=[0-9]+' | cut -d= -f2)"

        RESULT_EVENTS_PER_SEC["$key"]="$events_per_sec"
        RESULT_MB_PER_SEC["$key"]="$mb_per_sec"
        RESULT_LATENCY_US["$key"]="$latency_us"
        RESULT_RECONNECTS["$key"]="$reconnects"
        RESULT_LOST["$key"]="$lost"
    done
done

echo
printf "%-14s %-10s %14s %12s %18s %11s %8s\n" \
    "payload_size" "pipeline" "events/sec" "MB/sec" "avg_latency_us" "reconnects" "lost"
printf "%-14s %-10s %14s %12s %18s %11s %8s\n" \
    "--------------" "----------" "--------------" "------------" "------------------" "-----------" "--------"

for payload in "${PAYLOAD_SIZES[@]}"; do
    for pipeline in "${PIPELINES[@]}"; do
        key="${payload}_${pipeline}"
        printf "%-14s %-10s %14s %12s %18s %11s %8s\n" \
            "$payload" "$pipeline" \
            "${RESULT_EVENTS_PER_SEC[$key]:-N/A}" \
            "${RESULT_MB_PER_SEC[$key]:-N/A}" \
            "${RESULT_LATENCY_US[$key]:-N/A}" \
            "${RESULT_RECONNECTS[$key]:-N/A}" \
            "${RESULT_LOST[$key]:-N/A}"
    done
done
echo

# Sanity check: pipelining should measurably help. Compare pipeline=512 vs
# pipeline=1 throughput for the 2048-byte payload row.
p1_key="2048_1"
p512_key="2048_512"
p1_rate="${RESULT_EVENTS_PER_SEC[$p1_key]:-0}"
p512_rate="${RESULT_EVENTS_PER_SEC[$p512_key]:-0}"

if [[ -n "$p1_rate" && -n "$p512_rate" ]]; then
    ratio="$(awk -v a="$p512_rate" -v b="$p1_rate" 'BEGIN { if (b <= 0) { print "0" } else { printf "%.2f", a / b } }')"
    log "pipeline=512 vs pipeline=1 throughput ratio (payload=2048): ${ratio}x (${p512_rate} events/sec vs ${p1_rate} events/sec)"

    ok="$(awk -v r="$ratio" 'BEGIN { print (r > 2.0) ? "1" : "0" }')"
    if [[ "$ok" != "1" ]]; then
        log "WARNING: pipeline=512 throughput is NOT > 2x pipeline=1 throughput for payload=2048 (ratio=${ratio}x) -- pipelining may not be engaged as expected!"
        FAILED=1
    else
        log "sanity check OK: pipelining delivers > 2x throughput at pipeline=512 vs pipeline=1"
    fi
else
    log "WARNING: could not compute pipeline=1 vs pipeline=512 sanity ratio -- missing results"
    FAILED=1
fi

exit "$FAILED"
