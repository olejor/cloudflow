"""Builds representative CloudFlowEvent protos directly with the Python
bindings and emits their packed protobuf bytes as fixture inputs for the C
sink's golden-compatibility tests (WP-17, docs/splunk-output.md).

The WP-12 Python transform that these events used to be fed through has been
removed in the C rewrite; this module survives as the *golden generator* --
it is the oracle that produces the exact CloudFlowEvent bytes the committed
tests/golden/*.json goldens were derived from, so the C transform can be
proven structurally identical against the same inputs.

Run as a script to (re)write the packed fixtures the C test reads:

    PYTHONPATH=../src/cloudflow_pb python3 generate_fixtures.py [OUTDIR]

(default OUTDIR = ./fixtures next to this file). Each event is written as
<name>.pb (raw CloudFlowEvent.SerializeToString() bytes).

Uses documentation address space (RFC 5737 IPv4, RFC 3849 IPv6) and a
locally-administered MAC (Convention 6).
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running straight out of the checkout without setting PYTHONPATH: the
# generated bindings live next to the (now C-only) sink, under src/cloudflow_pb.
_HERE = Path(__file__).resolve().parent
_PB_ROOT = _HERE.parent / "src" / "cloudflow_pb"
if _PB_ROOT.is_dir() and str(_PB_ROOT) not in sys.path:
    sys.path.insert(0, str(_PB_ROOT))

from cloudflow.v1 import common_pb2, dhcp_pb2, dns_pb2
from cloudflow.v1.envelope_pb2 import CloudFlowEvent

CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:fe"


def _base_envelope(
    source_type: str,
    event_type: str,
    observed_ns: int,
    stream_name: str,
    *,
    source_host: str | None = None,
    payload_schema: str | None = None,
) -> common_pb2.EventEnvelope:
    if payload_schema is None:
        payload_schema = f"cloudflow.v1.{'DhcpV4PacketEvent' if source_type == 'dhcpv4' else 'DhcpV6PacketEvent'}"
    return common_pb2.EventEnvelope(
        event_id="ab12cd34ef56ab12cd34ef56ab12cd34",
        schema_version=1,
        source_type=source_type,
        source_host=source_host if source_host is not None else "dhcp-source-01.example.net",
        source_instance="dhcp-source-01",
        capture_interface="eth0",
        observation_method="rxring",
        observed_time_unix_nano=observed_ns,
        ingest_time_unix_nano=observed_ns + 500_000,
        event_type=event_type,
        visibility=common_pb2.VISIBILITY_PACKET_PAYLOAD,
        confidence=common_pb2.OBSERVATION_CONFIDENCE_OBSERVED,
        payload_schema=payload_schema,
        stream_name=stream_name,
    )


def _packet_observation(
    observed_ns: int,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    *,
    network_protocol=common_pb2.NetworkLayerObservation.NETWORK_PROTOCOL_IPV4,
    ethertype: int = 0x0800,
    dst_mac: str = "ff:ff:ff:ff:ff:ff",
) -> common_pb2.PacketObservation:
    return common_pb2.PacketObservation(
        observed_time_unix_nano=observed_ns,
        capture_direction=common_pb2.CAPTURE_DIRECTION_INGRESS,
        link=common_pb2.LinkLayerObservation(
            src_mac=CLIENT_MAC,
            dst_mac=dst_mac,
            vlan_ids=[100],
            ethertype=ethertype,
        ),
        network=common_pb2.NetworkLayerObservation(
            protocol=network_protocol,
            src_ip=src_ip,
            dst_ip=dst_ip,
            next_header=17,
            ttl_or_hop_limit=64,
        ),
        transport=common_pb2.TransportLayerObservation(
            protocol=common_pb2.TransportLayerObservation.TRANSPORT_PROTOCOL_UDP,
            ip_protocol_number=17,
            src_port=src_port,
            dst_port=dst_port,
            udp=common_pb2.UdpObservation(length=300, checksum_present=True, checksum_validated=True),
        ),
        packet_len=342,
        captured_len=342,
        truncated=False,
        rx_queue=0,
        rx_hash=123456789,
        capture_sequence=42,
    )


def dhcpv4_discover_event(*, with_raw_payload: bool = False) -> CloudFlowEvent:
    """A fully populated DHCPv4 DISCOVER, decoded options + envelope."""
    observed_ns = 1_730_000_000_123_456_789
    envelope = _base_envelope("dhcpv4", "dhcpv4.discover.observed", observed_ns, "cloudflow:v1:wire:dhcpv4")

    header = dhcp_pb2.DhcpV4Header(
        op=1,
        htype=1,
        hlen=6,
        hops=0,
        xid=0xDEADBEEF,
        secs=0,
        flags=0x8000,
        ciaddr="0.0.0.0",
        yiaddr="0.0.0.0",
        siaddr="0.0.0.0",
        giaddr="0.0.0.0",
        chaddr_raw=bytes.fromhex("020000000001") + b"\x00" * 10,
        chaddr_mac=CLIENT_MAC,
        magic_cookie_present=True,
    )

    raw_options = [
        dhcp_pb2.DhcpV4Option(
            code=53,
            name="dhcp_message_type",
            length=1,
            raw_value=bytes([1]),
            source_field=dhcp_pb2.DhcpV4Option.SOURCE_FIELD_OPTIONS,
            ordinal=0,
        ),
        dhcp_pb2.DhcpV4Option(
            code=55,
            name="parameter_request_list",
            length=4,
            raw_value=bytes([1, 3, 6, 15]),
            source_field=dhcp_pb2.DhcpV4Option.SOURCE_FIELD_OPTIONS,
            ordinal=1,
        ),
    ]

    decoded = dhcp_pb2.DhcpV4DecodedOptions(
        message_type=dhcp_pb2.DhcpV4DecodedOptions.DISCOVER,
        message_type_name="DISCOVER",
        parameter_request_list=[1, 3, 6, 15],
        max_dhcp_message_size=1500,
        vendor_class_identifier="cloudflow-test-client",
        client_identifier_raw=bytes.fromhex("01020000000001"),
        client_identifier_text="",
    )

    interpretation = dhcp_pb2.DhcpV4Interpretation(
        event_type="dhcpv4.discover.observed",
        transaction_key="deadbeef",
        normalized_client_key="02:00:00:00:00:01",
        is_relayed=False,
        is_broadcast=True,
        is_renewal=False,
        is_rebind=False,
    )

    packet_event = dhcp_pb2.DhcpV4PacketEvent(
        packet=_packet_observation(observed_ns, "198.51.100.10", "255.255.255.255", 68, 67),
        header=header,
        raw_options=raw_options,
        decoded=decoded,
        interpretation=interpretation,
    )
    if with_raw_payload:
        packet_event.raw_dhcp_payload = b"\x01\x01\x06\x00" + b"\xaa" * 236
        packet_event.raw_payload_truncated = False

    return CloudFlowEvent(envelope=envelope, dhcpv4_packet=packet_event)


def dhcpv6_solicit_event() -> CloudFlowEvent:
    """A representative DHCPv6 SOLICIT."""
    observed_ns = 1_730_000_001_987_654_321
    envelope = _base_envelope("dhcpv6", "dhcpv6.solicit.observed", observed_ns, "cloudflow:v1:wire:dhcpv6")

    header = dhcp_pb2.DhcpV6Header(
        message_type=dhcp_pb2.DhcpV6Header.SOLICIT,
        transaction_id=0x00A1B2,
    )

    raw_options = [
        dhcp_pb2.DhcpV6Option(
            code=1,
            name="client_id",
            length=14,
            raw_value=bytes.fromhex("00030001" + "020000000001"),
            ordinal=0,
        ),
        dhcp_pb2.DhcpV6Option(
            code=6,
            name="option_request",
            length=4,
            raw_value=bytes([0, 23, 0, 24]),
            ordinal=1,
        ),
    ]

    decoded = dhcp_pb2.DhcpV6DecodedOptions(
        client_duid=bytes.fromhex("00030001" + "020000000001"),
        option_request_option_codes=[23, 24],
    )

    packet_event = dhcp_pb2.DhcpV6PacketEvent(
        packet=_packet_observation(
            observed_ns,
            "2001:db8::10",
            "ff02::1:2",
            546,
            547,
            network_protocol=common_pb2.NetworkLayerObservation.NETWORK_PROTOCOL_IPV6,
            ethertype=0x86DD,
            dst_mac="33:33:00:01:00:02",
        ),
        header=header,
        raw_options=raw_options,
        decoded=decoded,
    )

    return CloudFlowEvent(envelope=envelope, dhcpv6_packet=packet_event)


def dns_transaction_event() -> CloudFlowEvent:
    """A fully-correlated client-facing DNS transaction: an A query matched to
    its NOERROR answer (mirrors the tests/fixtures/dns q_a_query/q_a_response
    pair). Exercises the `dns_transaction` oneof, both packet observations, a
    decoded question + answer, role, rtt, and the normalized client/server
    identity fields (dns.proto)."""
    query_ns = 1_730_000_002_000_000_000
    rtt_nanos = 1_234_567
    response_ns = query_ns + rtt_nanos

    envelope = _base_envelope(
        "dns",
        "dns.transaction.observed",
        query_ns,
        "cloudflow:v1:wire:dns",
        source_host="dns-source-01.example.net",
        payload_schema="cloudflow.v1.DnsTransactionEvent",
    )

    client_ip, client_port = "192.0.2.100", 40000
    server_ip = "192.0.2.53"

    question = dns_pb2.DnsQuestion(
        qname="www.example.com",
        qname_wire=b"\x03www\x07example\x03com\x00",
        qtype=1,
        qtype_name="A",
        qclass=1,
    )

    query = dns_pb2.DnsMessage(
        header=dns_pb2.DnsHeader(id=0x1234, rd=True, qdcount=1),
        questions=[question],
    )

    response = dns_pb2.DnsMessage(
        header=dns_pb2.DnsHeader(
            id=0x1234, qr=True, rd=True, ra=True, rcode=0, qdcount=1, ancount=1
        ),
        questions=[question],
        answers=[
            dns_pb2.DnsResourceRecord(
                name="www.example.com",
                type=1,
                type_name="A",
                **{"class": 1},
                ttl=300,
                rdata_raw=bytes([192, 0, 2, 10]),
                rdata_text="192.0.2.10",
            )
        ],
    )

    transaction = dns_pb2.DnsTransactionEvent(
        query_packet=_packet_observation(query_ns, client_ip, server_ip, client_port, 53),
        response_packet=_packet_observation(response_ns, server_ip, client_ip, 53, client_port),
        query=query,
        response=response,
        role=dns_pb2.DNS_LEG_CLIENT_FACING,
        rtt_nanos=rtt_nanos,
        rtt_valid=True,
        transaction_key="4660/www.example.com/A",
        client_ip=client_ip,
        client_port=client_port,
        server_ip=server_ip,
    )

    return CloudFlowEvent(envelope=envelope, dns_transaction=transaction)


# Fixture name -> builder. These names match tests/golden/<name>.json and the
# .pb files the C golden test reads from the fixtures directory.
FIXTURES = {
    "dhcpv4_discover": lambda: dhcpv4_discover_event(),
    "dhcpv4_discover_raw_payload_stripped": lambda: dhcpv4_discover_event(with_raw_payload=True),
    "dhcpv6_solicit": lambda: dhcpv6_solicit_event(),
    "dns_transaction": lambda: dns_transaction_event(),
}


def write_fixtures(outdir: Path) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    for name, build in FIXTURES.items():
        event = build()
        (outdir / f"{name}.pb").write_bytes(event.SerializeToString())
        print(f"wrote {outdir / (name + '.pb')}")


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    outdir = Path(argv[0]) if argv else (_HERE / "fixtures")
    write_fixtures(outdir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
