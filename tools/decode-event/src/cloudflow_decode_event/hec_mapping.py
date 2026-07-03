"""Canonical CloudFlowEvent -> Splunk HEC JSON mapping (vendored copy).

This is the same contract defined in docs/splunk-output.md
("Canonical HEC mapping"). It originally lived in the Python Splunk sink,
which was rewritten in C (WP-17); this tool stays Python, so it carries its
own faithful copy of the mapping for ``decode-event --hec``. The C sink's
transform (sinks/cloudflow-sink-splunk/src/transform.c) and this module are
kept in agreement by the shared golden files in
sinks/cloudflow-sink-splunk/tests/golden/. If the mapping changes, update
both and the goldens together.

Rules (verbatim from the contract):

- time = observed_time_unix_nano / 1e9, formatted with exactly 9 decimals,
  rendered as a JSON number.
- host = envelope.source_host.
- source = envelope.stream_name, falling back to the entry's stream.
- sourcetype from sourcetypes keyed by envelope.source_type; unknown types
  fall back to "cloudflow:<source_type>".
- index = config index, omitted entirely if empty.
- event = MessageToDict(preserving_proto_field_name=True) verbatim.
- raw_dhcp_payload stripped unless include_raw_payload.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, Tuple

from google.protobuf import json_format

# json.dumps always quotes a str value; we splice the raw 9-decimal numeral
# back in after encoding so `time` renders as a JSON number with no
# float-repr rounding. The placeholder is distinctive enough that no real
# event field is expected to contain it verbatim.
_TIME_PLACEHOLDER = "\x00__cloudflow_hec_time_placeholder__\x00"
_TIME_PLACEHOLDER_JSON = json.dumps(_TIME_PLACEHOLDER)


@dataclass
class SplunkConfig:
    """Just the fields the HEC mapping needs (a subset of the sink's config).

    ``decode-event`` has no operator config file, so the CLI constructs this
    with defaults: no index, no sourcetype overrides, raw payload stripped.
    """

    index: str = ""
    sourcetypes: Dict[str, str] = field(default_factory=dict)
    include_raw_payload: bool = False

    def sourcetype_for(self, source_type: str) -> str:
        configured = self.sourcetypes.get(source_type)
        if configured:
            return configured
        return f"cloudflow:{source_type}"


def format_hec_time(observed_time_unix_nano: int) -> str:
    """Render Unix-epoch nanoseconds as seconds with exactly 9 decimal places."""
    nanos = int(observed_time_unix_nano)
    sign = "-" if nanos < 0 else ""
    nanos = abs(nanos)
    secs, frac = divmod(nanos, 1_000_000_000)
    return f"{sign}{secs}.{frac:09d}"


def _strip_raw_payload(event_dict: Dict[str, Any], payload_field: str) -> None:
    payload = event_dict.get(payload_field)
    if isinstance(payload, dict):
        payload.pop("raw_dhcp_payload", None)


def event_to_hec_dict(cf_event, stream_name: str,
                      splunk_config: SplunkConfig) -> Tuple[Dict[str, Any], str]:
    """Build the HEC event dict (time as a placeholder) plus its time text."""
    envelope = cf_event.envelope

    event_dict = json_format.MessageToDict(cf_event, preserving_proto_field_name=True)
    if not splunk_config.include_raw_payload:
        payload_field = cf_event.WhichOneof("payload")
        if payload_field:
            _strip_raw_payload(event_dict, payload_field)

    source = envelope.stream_name or stream_name
    sourcetype = splunk_config.sourcetype_for(envelope.source_type)

    hec: Dict[str, Any] = {
        "time": _TIME_PLACEHOLDER,
        "host": envelope.source_host,
        "source": source,
        "sourcetype": sourcetype,
        "event": event_dict,
    }
    if splunk_config.index:
        hec["index"] = splunk_config.index

    return hec, format_hec_time(envelope.observed_time_unix_nano)


def render_hec_line(cf_event, stream_name: str, splunk_config: SplunkConfig,
                    sort_keys: bool = True) -> str:
    """Render one CloudFlowEvent as a single HEC JSON line (no trailing newline)."""
    hec_dict, time_text = event_to_hec_dict(cf_event, stream_name, splunk_config)
    text = json.dumps(hec_dict, sort_keys=sort_keys)
    return text.replace(_TIME_PLACEHOLDER_JSON, time_text)
