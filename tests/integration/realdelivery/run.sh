#!/usr/bin/env bash
#
# Real-delivery integration harness (project review G2).
#
# Brings up Redis + real ClickHouse + a fake Splunk HEC, replays committed pcap
# fixtures through the two sources, then runs the three sinks in REAL delivery
# mode (--once, no --stdout) so the actual HTTP POST / INSERT / retry /
# ack-after-2xx / dead-letter paths execute. Asserts that:
#   * the fake HEC received the expected DHCP + DNS events and metric points,
#   * ClickHouse has the corresponding rows (a real INSERT, not --stdout),
#   * every consumer group is fully acked (0 pending),
#   * no dead-letter entries on the happy path.
#
# Requires docker + the compose plugin. Run from anywhere:
#   tests/integration/realdelivery/run.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

COMPOSE=(docker compose)
WORK="$HERE/work"
REC="$WORK/hec_received.jsonl"

DHCPV4_STREAM="cloudflow:v1:wire:dhcpv4"
DNS_STREAM="cloudflow:v1:wire:dns"

log()  { printf '[harness] %s\n' "$*"; }
fail() { printf '[harness] FAIL: %s\n' "$*" >&2; exit 1; }

cleanup() {
    log "tearing down"
    "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ---- 0. clean slate ------------------------------------------------------
rm -rf "$WORK"
mkdir -p "$WORK"

# The DNS source correlates a query with its response only if both arrive in
# one --replay run, so concatenate the committed pair into one pcap (keeping a
# single 24-byte global header), exactly as the plain integration script does.
python3 - "$HERE/../../fixtures/dns/q_a_query.pcap" \
           "$HERE/../../fixtures/dns/q_a_response.pcap" \
           "$WORK/q_a_pair.pcap" <<'PY'
import sys
q = open(sys.argv[1], "rb").read()
r = open(sys.argv[2], "rb").read()
if q[:24] != r[:24]:
    sys.exit("DNS fixture pcaps have differing global headers; cannot concatenate")
open(sys.argv[3], "wb").write(q + r[24:])
PY
chmod 0644 "$WORK/q_a_pair.pcap"

# ---- 1. build the app image + start infra --------------------------------
log "building app image"
"${COMPOSE[@]}" build

log "starting infra (redis, clickhouse, hecfake)"
"${COMPOSE[@]}" up -d redis clickhouse hecfake

# Bounded wait for all infra to report healthy (better errors than letting the
# first `run` block on it).
log "waiting for infra healthy"
for svc in redis clickhouse hecfake; do
    for _ in $(seq 1 60); do
        state="$("${COMPOSE[@]}" ps "$svc" --format '{{.Health}}' 2>/dev/null || true)"
        [[ "$state" == "healthy" ]] && break
        sleep 2
    done
    [[ "$state" == "healthy" ]] || { "${COMPOSE[@]}" logs "$svc" || true; fail "$svc did not become healthy"; }
    log "  $svc healthy"
done

# The clickhouse healthcheck (SELECT 1) can go green before the initdb schema
# under /docker-entrypoint-initdb.d has finished applying, so wait explicitly
# for the table to exist before anything tries to INSERT into it.
log "waiting for the ClickHouse schema (cloudflow.events)"
for _ in $(seq 1 30); do
    exists="$("${COMPOSE[@]}" exec -T clickhouse clickhouse-client -q "EXISTS TABLE cloudflow.events" 2>/dev/null | tr -dc '0-9' || true)"
    [[ "$exists" == "1" ]] && break
    sleep 2
done
[[ "${exists:-}" == "1" ]] || fail "cloudflow.events did not appear (schema init failed?)"

run_app() { "${COMPOSE[@]}" run --rm "$@"; }
redis_cli() { "${COMPOSE[@]}" exec -T redis redis-cli "$@"; }
# Extract a single integer from a redis reply robustly: take the last token of
# the first line and strip non-digits, so it works whether redis-cli emits raw
# ("0") or decorated ("1) (integer) 0", "(integer) 5") output.
redis_int() { redis_cli "$@" | awk 'NR==1{n=$NF; gsub(/[^0-9]/,"",n); print n; exit}'; }
# clickhouse-client -q returns a bare number; strip to digits defensively.
ch_count() { "${COMPOSE[@]}" exec -T clickhouse clickhouse-client -q "$1" | tr -dc '0-9'; }

# ---- 2. replay fixtures through the sources ------------------------------
log "replaying DHCP fixtures through the DHCP source"
for pcap in v4_discover v4_ack; do
    run_app dhcp-source cloudflow-source-dhcp -c /configs/dhcp-source.yaml \
        --replay "/fixtures/dhcp/${pcap}.pcap"
done

log "replaying the DNS query+response pair through the DNS source"
run_app dns-source cloudflow-source-dns -c /configs/dns-source.yaml \
    --replay /work/q_a_pair.pcap

v4_xlen="$(redis_int XLEN "$DHCPV4_STREAM")"
dns_xlen="$(redis_int XLEN "$DNS_STREAM")"
log "XLEN $DHCPV4_STREAM = $v4_xlen, XLEN $DNS_STREAM = $dns_xlen"
[[ "$v4_xlen" -ge 2 ]] || fail "expected >=2 dhcpv4 events, got $v4_xlen"
[[ "$dns_xlen" == "1" ]] || fail "expected exactly 1 correlated DNS transaction, got $dns_xlen"

# ---- 3. run the three sinks in REAL delivery mode ------------------------
log "delivering: splunk event sink -> fake HEC"
run_app splunk-sink cloudflow-sink-splunk -c /configs/splunk-sink.yaml --once
log "delivering: splunk metrics sink -> fake HEC"
run_app splunk-metrics-sink cloudflow-sink-splunk-metrics -c /configs/splunk-metrics.yaml --once
log "delivering: clickhouse sink -> real ClickHouse"
run_app clickhouse-sink cloudflow-sink-clickhouse -c /configs/clickhouse-sink.yaml --once

# ---- 4. assert the fake HEC received the events + metric points ----------
[[ -s "$REC" ]] || fail "fake HEC recorded nothing at $REC"
log "asserting fake HEC contents ($(wc -l <"$REC") records)"
python3 - "$REC" <<'PY'
import json, sys
recs = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
events  = [r["event"] for r in recs if r["path"].endswith("/services/collector/event")]
metrics = [r["event"] for r in recs if r["path"] == "/services/collector"]

st = {e.get("sourcetype") for e in events}
if not any(s == "cloudflow:dhcpv4" for s in st):
    sys.exit(f"FAIL: no cloudflow:dhcpv4 HEC event delivered (sourcetypes={st})")
if not any(s == "cloudflow:dns" for s in st):
    sys.exit(f"FAIL: no cloudflow:dns HEC event delivered (sourcetypes={st})")

# The DNS transaction must have produced at least one dimensioned metric point.
mnames = set()
for m in metrics:
    mnames |= {k.split(":", 1)[1] for k in m.get("fields", {}) if k.startswith("metric_name:")}
if not ({"dns.transactions_total", "dns.rtt_seconds"} & mnames):
    sys.exit(f"FAIL: no DNS metric point delivered (metric_names={mnames})")

print(f"OK: HEC received {len(events)} events (sourcetypes={st}) and "
      f"{len(metrics)} metric points (metric_names={mnames})")
PY

# ---- 5. assert ClickHouse actually stored the rows -----------------------
log "asserting ClickHouse rows"
ch_total="$(ch_count 'SELECT count() FROM cloudflow.events')"
ch_dns="$(ch_count "SELECT count() FROM cloudflow.events WHERE source_type = 'dns'")"
log "ClickHouse: total rows = $ch_total, dns rows = $ch_dns"
[[ "$ch_total" -ge 3 ]] || fail "expected >=3 rows in ClickHouse, got $ch_total"
[[ "$ch_dns" -ge 1 ]]   || fail "expected a dns row in ClickHouse, got $ch_dns"

# ---- 6. assert every consumer group is fully acked, no dead-letter -------
log "asserting 0 pending + empty dead-letter streams"
for grp in sink-splunk sink-splunk-metrics sink-clickhouse; do
    for stream in "$DHCPV4_STREAM" "$DNS_STREAM"; do
        pend="$(redis_int XPENDING "$stream" "$grp")"
        [[ "$pend" == "0" ]] || fail "group $grp on $stream has $pend pending (expected 0)"
    done
done
for dl in cloudflow:v1:deadletter:sink-splunk \
          cloudflow:v1:deadletter:sink-splunk-metrics \
          cloudflow:v1:deadletter:sink-clickhouse; do
    dl_len="$(redis_int XLEN "$dl")"
    [[ "$dl_len" == "0" ]] || fail "dead-letter stream $dl is non-empty ($dl_len) on the happy path"
done

log "PASS: real HTTP delivery to the fake HEC + real INSERT into ClickHouse verified; all groups acked, no dead-letter."
