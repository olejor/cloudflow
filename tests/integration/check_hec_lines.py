#!/usr/bin/env python3
"""WP-14 structural assertions for cloudflow-sink-splunk's `--stdout` output.

Given the newline-concatenated HEC-shaped JSON lines produced by
`cloudflow-sink-splunk -c ... --once --stdout` against a freshly replayed
fixture corpus, checks:

  - the line count equals the expected total (sum of both wire streams'
    expected counts from tests/integration/expected_counts.tsv);
  - each line parses as JSON and has the canonical HEC envelope shape
    (docs/splunk-output.md "Canonical HEC mapping"): `time` a number,
    `host`/`source`/`sourcetype` non-empty strings, `event` an object;
  - `event.envelope.source_type` is dhcpv4 or dhcpv6 and the matching oneof
    payload (`dhcpv4_packet`/`dhcpv6_packet`) is present;
  - `raw_dhcp_payload` is absent (default `splunk.include_raw_payload: false`
    strips it);
  - per-stream counts match the expected split;
  - one spot check per DHCP family tying `sourcetype` to a decoded field:
    the v4 DISCOVER fixture's line has `sourcetype=cloudflow:dhcpv4` and
    `event.dhcpv4_packet.decoded.message_type_name == "DISCOVER"`; the v6
    SOLICIT fixture's line has `sourcetype=cloudflow:dhcpv6` and
    `event.dhcpv6_packet.header.message_type == "SOLICIT"`.

This does *not* byte-diff against the WP-12 golden files: `ingest_time_unix_nano`
is non-deterministic per run (set at replay time), so only structural /
spot-check assertions are made here (per the WP-14 task -- the golden files
remain the transform-mapping oracle, exercised independently by the sink's
own `make test`).

Exit 0 and print a short summary on success; exit 1 with a description of
the first failure otherwise.
"""

from __future__ import annotations

import argparse
import json
import sys

REQUIRED_TOP_KEYS = ("time", "host", "source", "sourcetype", "event")
SOURCETYPE_BY_SOURCE_TYPE = {
    "dhcpv4": "cloudflow:dhcpv4",
    "dhcpv6": "cloudflow:dhcpv6",
}
PACKET_FIELD_BY_SOURCE_TYPE = {
    "dhcpv4": "dhcpv4_packet",
    "dhcpv6": "dhcpv6_packet",
}


class Fail(Exception):
    pass


def check_line(lineno: int, obj) -> str:
    """Validate one parsed HEC line; return its envelope source_type."""
    if not isinstance(obj, dict):
        raise Fail(f"line {lineno}: top-level JSON is not an object")

    for key in REQUIRED_TOP_KEYS:
        if key not in obj:
            raise Fail(f"line {lineno}: missing required HEC key {key!r}")

    if not isinstance(obj["time"], (int, float)) or isinstance(obj["time"], bool):
        raise Fail(f"line {lineno}: 'time' is not a number: {obj['time']!r}")
    if obj["time"] <= 0:
        raise Fail(f"line {lineno}: 'time' is not positive: {obj['time']!r}")

    for key in ("host", "source", "sourcetype"):
        if not isinstance(obj[key], str) or not obj[key]:
            raise Fail(f"line {lineno}: {key!r} is not a non-empty string: {obj[key]!r}")

    if not obj["source"].startswith("cloudflow:v1:wire:"):
        raise Fail(f"line {lineno}: 'source' does not look like a wire stream: {obj['source']!r}")

    event = obj["event"]
    if not isinstance(event, dict):
        raise Fail(f"line {lineno}: 'event' is not an object")

    envelope = event.get("envelope")
    if not isinstance(envelope, dict):
        raise Fail(f"line {lineno}: event.envelope missing or not an object")

    source_type = envelope.get("source_type")
    if source_type not in SOURCETYPE_BY_SOURCE_TYPE:
        raise Fail(f"line {lineno}: unexpected envelope.source_type {source_type!r}")

    expected_sourcetype = SOURCETYPE_BY_SOURCE_TYPE[source_type]
    if obj["sourcetype"] != expected_sourcetype:
        raise Fail(
            f"line {lineno}: sourcetype {obj['sourcetype']!r} does not match "
            f"source_type {source_type!r} (expected {expected_sourcetype!r})"
        )

    packet_field = PACKET_FIELD_BY_SOURCE_TYPE[source_type]
    packet = event.get(packet_field)
    if not isinstance(packet, dict):
        raise Fail(f"line {lineno}: event.{packet_field} missing or not an object")

    if "raw_dhcp_payload" in packet:
        raise Fail(
            f"line {lineno}: event.{packet_field}.raw_dhcp_payload present "
            "(include_raw_payload defaults to false)"
        )

    if not envelope.get("event_id"):
        raise Fail(f"line {lineno}: event.envelope.event_id missing/empty")

    return source_type, envelope.get("event_type", ""), packet


def spot_check_v4_discover(lines_info) -> None:
    for lineno, obj, source_type, event_type, packet in lines_info:
        if source_type == "dhcpv4" and event_type == "dhcpv4.discover.observed":
            if obj["sourcetype"] != "cloudflow:dhcpv4":
                raise Fail(
                    f"line {lineno}: v4 discover sourcetype = {obj['sourcetype']!r}, "
                    "expected cloudflow:dhcpv4"
                )
            name = packet.get("decoded", {}).get("message_type_name")
            if name != "DISCOVER":
                raise Fail(
                    f"line {lineno}: v4 discover decoded.message_type_name = {name!r}, "
                    "expected DISCOVER"
                )
            return
    raise Fail("no dhcpv4.discover.observed line found (v4_discover fixture spot check)")


def spot_check_v6_solicit(lines_info) -> None:
    for lineno, obj, source_type, event_type, packet in lines_info:
        if source_type == "dhcpv6" and event_type == "dhcpv6.solicit.observed":
            if obj["sourcetype"] != "cloudflow:dhcpv6":
                raise Fail(
                    f"line {lineno}: v6 solicit sourcetype = {obj['sourcetype']!r}, "
                    "expected cloudflow:dhcpv6"
                )
            mtype = packet.get("header", {}).get("message_type")
            if mtype != "SOLICIT":
                raise Fail(
                    f"line {lineno}: v6 solicit header.message_type = {mtype!r}, "
                    "expected SOLICIT"
                )
            return
    raise Fail("no dhcpv6.solicit.observed line found (v6_solicit fixture spot check)")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lines_file", help="path to captured --stdout HEC JSON lines")
    parser.add_argument("--dhcpv4-count", type=int, required=True)
    parser.add_argument("--dhcpv6-count", type=int, required=True)
    ns = parser.parse_args(argv)

    with open(ns.lines_file, "r", encoding="utf-8") as f:
        raw_lines = [ln for ln in f.read().splitlines() if ln.strip()]

    expected_total = ns.dhcpv4_count + ns.dhcpv6_count
    if len(raw_lines) != expected_total:
        print(
            f"FAIL: got {len(raw_lines)} HEC lines, expected {expected_total} "
            f"({ns.dhcpv4_count} dhcpv4 + {ns.dhcpv6_count} dhcpv6)",
            file=sys.stderr,
        )
        return 1

    lines_info = []
    counts = {"dhcpv4": 0, "dhcpv6": 0}
    try:
        for i, raw in enumerate(raw_lines, start=1):
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError as e:
                raise Fail(f"line {i}: not valid JSON: {e}")
            source_type, event_type, packet = check_line(i, obj)
            counts[source_type] += 1
            lines_info.append((i, obj, source_type, event_type, packet))

        if counts["dhcpv4"] != ns.dhcpv4_count:
            raise Fail(f"dhcpv4 line count {counts['dhcpv4']} != expected {ns.dhcpv4_count}")
        if counts["dhcpv6"] != ns.dhcpv6_count:
            raise Fail(f"dhcpv6 line count {counts['dhcpv6']} != expected {ns.dhcpv6_count}")

        spot_check_v4_discover(lines_info)
        spot_check_v6_solicit(lines_info)
    except Fail as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 1

    print(
        f"OK: {len(raw_lines)} HEC lines structurally valid "
        f"({counts['dhcpv4']} dhcpv4, {counts['dhcpv6']} dhcpv6); "
        "v4 DISCOVER and v6 SOLICIT spot checks passed"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
