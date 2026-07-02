"""Golden transform tests (docs/design/04-sink-splunk.md acceptance criteria).

For each fixture-derived CloudFlowEvent, the HEC JSON produced by
transform.render_hec_line() must match a committed golden file byte-for-byte
with stable key order (json.dumps(..., sort_keys=True), as in --stdout
mode).
"""

from __future__ import annotations

from pathlib import Path

import fixtures
import pytest

from cloudflow_sink_splunk import config, transform

GOLDEN_DIR = Path(__file__).parent / "golden"


def _splunk_config(**overrides):
    defaults = dict(
        hec_url="https://splunk.example.com:8088/services/collector/event",
        hec_token_env="SPLUNK_HEC_TOKEN",
        index="network",
        sourcetypes={"dhcpv4": "cloudflow:dhcpv4", "dhcpv6": "cloudflow:dhcpv6"},
    )
    defaults.update(overrides)
    return config.SplunkConfig(**defaults)


CASES = [
    pytest.param(
        "dhcpv4_discover.json",
        lambda: fixtures.dhcpv4_discover_event(),
        "cloudflow:v1:wire:dhcpv4",
        id="dhcpv4-discover",
    ),
    pytest.param(
        "dhcpv4_discover_raw_payload_stripped.json",
        lambda: fixtures.dhcpv4_discover_event(with_raw_payload=True),
        "cloudflow:v1:wire:dhcpv4",
        id="dhcpv4-discover-raw-payload-stripped",
    ),
    pytest.param(
        "dhcpv6_solicit.json",
        lambda: fixtures.dhcpv6_solicit_event(),
        "cloudflow:v1:wire:dhcpv6",
        id="dhcpv6-solicit",
    ),
]


@pytest.mark.parametrize("golden_name,build_event,stream_name", CASES)
def test_golden_transform_matches_byte_for_byte(golden_name, build_event, stream_name):
    splunk_cfg = _splunk_config()
    event = build_event()

    line = transform.render_hec_line(event, stream_name, splunk_cfg, sort_keys=True)

    golden_path = GOLDEN_DIR / golden_name
    expected = golden_path.read_text()
    assert expected.endswith("\n")
    assert line == expected[:-1], f"transform output does not match {golden_path}"


def test_raw_dhcp_payload_is_stripped_by_default():
    splunk_cfg = _splunk_config()
    event = fixtures.dhcpv4_discover_event(with_raw_payload=True)
    line = transform.render_hec_line(event, "cloudflow:v1:wire:dhcpv4", splunk_cfg)
    assert "raw_dhcp_payload" not in line


def test_raw_dhcp_payload_kept_when_configured():
    splunk_cfg = _splunk_config(include_raw_payload=True)
    event = fixtures.dhcpv4_discover_event(with_raw_payload=True)
    line = transform.render_hec_line(event, "cloudflow:v1:wire:dhcpv4", splunk_cfg)
    assert "raw_dhcp_payload" in line


def test_index_omitted_when_empty():
    splunk_cfg = _splunk_config(index="")
    event = fixtures.dhcpv4_discover_event()
    line = transform.render_hec_line(event, "cloudflow:v1:wire:dhcpv4", splunk_cfg)
    import json

    parsed = json.loads(line)
    assert "index" not in parsed


def test_sourcetype_fallback_for_unknown_source_type():
    splunk_cfg = _splunk_config(sourcetypes={})
    event = fixtures.dhcpv4_discover_event()
    line = transform.render_hec_line(event, "cloudflow:v1:wire:dhcpv4", splunk_cfg)
    import json

    parsed = json.loads(line)
    assert parsed["sourcetype"] == "cloudflow:dhcpv4"


def test_source_falls_back_to_stream_name_when_envelope_lacks_one():
    splunk_cfg = _splunk_config()
    event = fixtures.dhcpv4_discover_event()
    event.envelope.stream_name = ""
    line = transform.render_hec_line(event, "cloudflow:v1:wire:dhcpv4", splunk_cfg)
    import json

    parsed = json.loads(line)
    assert parsed["source"] == "cloudflow:v1:wire:dhcpv4"


def test_time_has_exactly_nine_decimal_places():
    assert transform.format_hec_time(1_730_000_000_123_456_789) == "1730000000.123456789"
    assert transform.format_hec_time(1_730_000_000_000_000_000) == "1730000000.000000000"
    assert transform.format_hec_time(0) == "0.000000000"
