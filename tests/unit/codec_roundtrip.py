#!/usr/bin/env python3
"""WP-02 round-trip acceptance check for the generated Python protobuf
bindings (mirrors tests/unit/cf_codec_test.c on the C side).

Imports the generated cloudflow_pb package, builds a CloudFlowEvent with an
EventEnvelope and a DhcpV4PacketEvent oneof payload, serializes it,
reparses it, and asserts the fields/oneof case survive.

Requires sinks/cloudflow-sink-splunk/src/cloudflow_pb on PYTHONPATH (see
sinks/cloudflow-sink-splunk/src/cloudflow_pb/README.md for why -- the
generated *_pb2.py files cross-import each other as `from cloudflow.v1
import ..._pb2`, so the directory *containing* the `cloudflow/` package,
not its parent, must be on the path); tests/unit/Makefile sets this when
invoking the script as part of `make test` / `test-unit`.
"""
import sys

from cloudflow.v1 import envelope_pb2


def build_event():
    event = envelope_pb2.CloudFlowEvent()
    event.envelope.event_id = "0123456789abcdef0123456789abcdef"
    event.envelope.schema_version = 1
    event.envelope.source_type = "dhcpv4"
    event.envelope.event_type = "dhcpv4.discover.observed"

    event.dhcpv4_packet.header.op = 1
    event.dhcpv4_packet.header.xid = 0xDEADBEEF
    event.dhcpv4_packet.header.ciaddr = "0.0.0.0"
    event.dhcpv4_packet.header.yiaddr = "0.0.0.0"

    return event


def main():
    original = build_event()

    packed = original.SerializeToString()
    assert len(packed) > 0, "serialized CloudFlowEvent must not be empty"

    reparsed = envelope_pb2.CloudFlowEvent()
    reparsed.ParseFromString(packed)

    assert reparsed.envelope.event_id == original.envelope.event_id
    assert reparsed.envelope.schema_version == original.envelope.schema_version
    assert reparsed.envelope.source_type == original.envelope.source_type
    assert reparsed.envelope.event_type == original.envelope.event_type

    assert reparsed.WhichOneof("payload") == "dhcpv4_packet"
    assert reparsed.dhcpv4_packet.header.op == original.dhcpv4_packet.header.op
    assert reparsed.dhcpv4_packet.header.xid == original.dhcpv4_packet.header.xid
    assert reparsed.dhcpv4_packet.header.ciaddr == original.dhcpv4_packet.header.ciaddr

    assert reparsed == original

    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
