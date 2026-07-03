"""Builds representative CloudFlowEvent protos directly with the Python
bindings (docs/design/04-sink-splunk.md acceptance criteria: "...or by
generate_fixtures.py building events directly with the Python bindings
until those [WP-06/07 round-trip fixtures] land" -- they have not landed
yet, so this module is that fallback).

Uses documentation address space (RFC 5737 IPv4, RFC 3849 IPv6) and a
locally-administered MAC (Convention 6).
"""

from __future__ import annotations

from cloudflow.v1 import common_pb2, dhcp_pb2
from cloudflow.v1.envelope_pb2 import CloudFlowEvent

CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:fe"


def _base_envelope(source_type: str, event_type: str, observed_ns: int, stream_name: str) -> common_pb2.EventEnvelope:
    return common_pb2.EventEnvelope(
        event_id="ab12cd34ef56ab12cd34ef56ab12cd34",
        schema_version=1,
        source_type=source_type,
        source_host="dhcp-source-01.example.net",
        source_instance="dhcp-source-01",
        capture_interface="eth0",
        observation_method="rxring",
        observed_time_unix_nano=observed_ns,
        ingest_time_unix_nano=observed_ns + 500_000,
        event_type=event_type,
        visibility=common_pb2.VISIBILITY_PACKET_PAYLOAD,
        confidence=common_pb2.OBSERVATION_CONFIDENCE_OBSERVED,
        payload_schema=f"cloudflow.v1.{'DhcpV4PacketEvent' if source_type == 'dhcpv4' else 'DhcpV6PacketEvent'}",
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
