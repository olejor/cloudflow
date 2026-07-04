#!/usr/bin/env python3
"""WP-DNS08 structural assertions for the DNS leg of the integration test.

Given the newline-concatenated HEC-shaped JSON produced by
`cloudflow-sink-splunk -c ... --once --stdout` over `cloudflow:v1:wire:dns`
after replaying the committed tests/fixtures/dns q_a query+response pair
through cloudflow-source-dns, checks the milestone M-DNS1 shape
(docs/splunk-output.md "Canonical HEC mapping"):

  - exactly one HEC line;
  - the canonical HEC envelope (time a number, host/source/sourcetype
    non-empty strings, event an object);
  - `sourcetype == "cloudflow:dns"` and `source == "cloudflow:v1:wire:dns"`;
  - `event.envelope.source_type == "dns"` and
    `event.envelope.event_type == "dns.transaction.observed"`;
  - the set oneof payload appears under `event.dns_transaction`;
  - a decoded question is present (query.questions[0] with a non-empty
    qname and a qtype_name);
  - the round-trip is sane: `rtt_valid` is true and `rtt_nanos` (a 64-bit int
    rendered as a JSON string, defaulting to 0 when omitted) is non-negative
    and below a 10s ceiling. NOTE: the committed fixtures carry identical pcap
    record timestamps for the query and response, so replay yields rtt_nanos=0
    (omitted) with rtt_valid=true -- a sane zero rtt, not a missing one.

Exit 0 with a short summary on success; exit 1 describing the first failure.
"""

from __future__ import annotations

import argparse
import json
import sys

REQUIRED_TOP_KEYS = ("time", "host", "source", "sourcetype", "event")
RTT_CEILING_NANOS = 10_000_000_000  # 10s: anything larger is not a sane DNS rtt


class Fail(Exception):
    pass


def check(obj) -> None:
    if not isinstance(obj, dict):
        raise Fail("top-level JSON is not an object")

    for key in REQUIRED_TOP_KEYS:
        if key not in obj:
            raise Fail(f"missing required HEC key {key!r}")

    if not isinstance(obj["time"], (int, float)) or isinstance(obj["time"], bool):
        raise Fail(f"'time' is not a number: {obj['time']!r}")
    if obj["time"] <= 0:
        raise Fail(f"'time' is not positive: {obj['time']!r}")

    for key in ("host", "source", "sourcetype"):
        if not isinstance(obj[key], str) or not obj[key]:
            raise Fail(f"{key!r} is not a non-empty string: {obj[key]!r}")

    if obj["sourcetype"] != "cloudflow:dns":
        raise Fail(f"sourcetype {obj['sourcetype']!r} != 'cloudflow:dns'")
    if obj["source"] != "cloudflow:v1:wire:dns":
        raise Fail(f"source {obj['source']!r} != 'cloudflow:v1:wire:dns'")

    event = obj["event"]
    if not isinstance(event, dict):
        raise Fail("'event' is not an object")

    envelope = event.get("envelope")
    if not isinstance(envelope, dict):
        raise Fail("event.envelope missing or not an object")
    if envelope.get("source_type") != "dns":
        raise Fail(f"envelope.source_type {envelope.get('source_type')!r} != 'dns'")
    if envelope.get("event_type") != "dns.transaction.observed":
        raise Fail(
            f"envelope.event_type {envelope.get('event_type')!r} != 'dns.transaction.observed'"
        )
    if not envelope.get("event_id"):
        raise Fail("event.envelope.event_id missing/empty")

    dt = event.get("dns_transaction")
    if not isinstance(dt, dict):
        raise Fail("event.dns_transaction (set oneof payload) missing or not an object")

    # decoded question (query side; responses echo the same question)
    query = dt.get("query")
    if not isinstance(query, dict):
        raise Fail("dns_transaction.query missing or not an object")
    questions = query.get("questions")
    if not isinstance(questions, list) or not questions:
        raise Fail("dns_transaction.query.questions missing/empty (no decoded question)")
    q0 = questions[0]
    if not isinstance(q0, dict) or not q0.get("qname"):
        raise Fail("decoded question has no qname")
    if not q0.get("qtype_name"):
        raise Fail("decoded question has no qtype_name")

    # sane rtt: valid, non-negative, below the ceiling (rtt_nanos is an int64
    # rendered as a string; omitted => 0 => a sane zero rtt).
    if dt.get("rtt_valid") is not True:
        raise Fail(f"dns_transaction.rtt_valid is not true: {dt.get('rtt_valid')!r}")
    rtt_raw = dt.get("rtt_nanos", "0")
    try:
        rtt = int(rtt_raw)
    except (TypeError, ValueError):
        raise Fail(f"dns_transaction.rtt_nanos not an integer: {rtt_raw!r}")
    if rtt < 0 or rtt >= RTT_CEILING_NANOS:
        raise Fail(f"dns_transaction.rtt_nanos {rtt} is not sane (0 <= rtt < {RTT_CEILING_NANOS})")

    return q0.get("qname"), q0.get("qtype_name"), rtt


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lines_file", help="path to captured --stdout HEC JSON lines")
    parser.add_argument("--count", type=int, default=1, help="expected HEC line count")
    ns = parser.parse_args(argv)

    with open(ns.lines_file, "r", encoding="utf-8") as f:
        raw_lines = [ln for ln in f.read().splitlines() if ln.strip()]

    if len(raw_lines) != ns.count:
        print(
            f"FAIL: got {len(raw_lines)} HEC lines, expected {ns.count}",
            file=sys.stderr,
        )
        return 1

    try:
        obj = json.loads(raw_lines[0])
    except json.JSONDecodeError as e:
        print(f"FAIL: line 1 not valid JSON: {e}", file=sys.stderr)
        return 1

    try:
        qname, qtype_name, rtt = check(obj)
    except Fail as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 1

    print(
        f"OK: 1 dns.transaction.observed HEC line, sourcetype=cloudflow:dns, "
        f"question={qname}/{qtype_name}, rtt_valid=true rtt_nanos={rtt}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
