"""protobuf CloudFlowEvent -> Splunk HEC JSON (the canonical mapping).

This is a contract (docs/design/04-sink-splunk.md, "Canonical HEC mapping"):
`tools/decode-event` (WP-13) reuses the same rules, and changing them later
is a schema change. Implement every rule exactly as specced:

- time = observed_time_unix_nano / 1e9, formatted with 9 decimal places.
- host = envelope.source_host.
- source = envelope.stream_name, falling back to the stream the entry came
  from.
- sourcetype from config splunk.sourcetypes keyed by envelope.source_type;
  unknown source types fall back to "cloudflow:<source_type>".
- index = config splunk.index, omitted entirely if empty.
- event = google.protobuf.json_format.MessageToDict(cloudflow_event,
  preserving_proto_field_name=True) verbatim -- do not hand-roll the
  conversion. That keeps bytes-as-base64, enums-as-names, and
  defaults-omitted behavior exactly as protobuf's own JSON mapping defines
  it, and keeps the oneof payload under its field name
  (dhcpv4_packet/dhcpv6_packet).
- raw_dhcp_payload is stripped from the decoded event by default (config
  splunk.include_raw_payload=false).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Dict, Tuple

from google.protobuf import json_format

if TYPE_CHECKING:  # pragma: no cover
    from cloudflow.v1.envelope_pb2 import CloudFlowEvent

    from .config import SplunkConfig

# json.dumps will always quote a python str value; we swap the quoted
# placeholder for the raw, exactly-9-decimal-place numeral after encoding so
# `time` renders as a JSON number (not a string) with no float-repr rounding
# or trailing-zero loss. The token is arbitrary but distinctive enough that
# no real event field is expected to contain it verbatim.
_TIME_PLACEHOLDER = "\x00__cloudflow_hec_time_placeholder__\x00"
_TIME_PLACEHOLDER_JSON = json.dumps(_TIME_PLACEHOLDER)


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


def event_to_hec_dict(
    cf_event: "CloudFlowEvent",
    stream_name: str,
    splunk_config: "SplunkConfig",
) -> Tuple[Dict[str, Any], str]:
    """Build the HEC event dict (time left as a placeholder) plus its time text.

    Returns (hec_dict, time_text). Callers that need a real JSON line should
    use render_hec_line() instead, which splices the two together correctly.
    """
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


def render_hec_line(
    cf_event: "CloudFlowEvent",
    stream_name: str,
    splunk_config: "SplunkConfig",
    sort_keys: bool = True,
) -> str:
    """Render one CloudFlowEvent as a single HEC JSON line (no trailing newline)."""
    hec_dict, time_text = event_to_hec_dict(cf_event, stream_name, splunk_config)
    text = json.dumps(hec_dict, sort_keys=sort_keys)
    return text.replace(_TIME_PLACEHOLDER_JSON, time_text)
