"""Builds representative CloudFlowEvent protos and emits their packed bytes as
fixture inputs for the ClickHouse sink's golden tests (WP-CH02,
docs/clickhouse-sink.md).

Same pattern as the Splunk sinks' generators (sinks/cloudflow-sink-splunk*/
tests/generate_fixtures.py): it is the *golden generator* -- the oracle that
produces the exact CloudFlowEvent bytes the committed tests/golden/*.jsonl
goldens were derived from, so the C row transform can be proven against the same
inputs. The two fixtures mirror the metrics sink's (a client-facing DNS
transaction with a service_role, and a DHCPv4 DISCOVER) so the goldens exercise
the DNS and DHCP column families.

The protobuf Python bindings are shared with the event sink (the committed
cloudflow.v1 bindings under sinks/cloudflow-sink-splunk/src/cloudflow_pb); this
script locates them relative to the repo root so no PYTHONPATH is needed.

Run to (re)write the packed fixtures the C test reads:

    python3 generate_fixtures.py [OUTDIR]

(default OUTDIR = ./fixtures next to this file). Each event is written as
<name>.pb (raw CloudFlowEvent.SerializeToString() bytes).

Uses documentation address space (RFC 5737 IPv4, RFC 3849 IPv6) and a
locally-administered MAC (Convention 6).
"""

from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
# Shared, committed bindings live with the event sink.
_PB_ROOT = _HERE.parent.parent / "cloudflow-sink-splunk" / "src" / "cloudflow_pb"
if _PB_ROOT.is_dir() and str(_PB_ROOT) not in sys.path:
    sys.path.insert(0, str(_PB_ROOT))

from cloudflow.v1 import common_pb2, dhcp_pb2, dns_pb2
from cloudflow.v1.envelope_pb2 import CloudFlowEvent

CLIENT_MAC = "02:00:00:00:00:01"


def _base_envelope(source_type, event_type, observed_ns, stream_name, source_host, payload_schema):
    return common_pb2.EventEnvelope(
        event_id="ab12cd34ef56ab12cd34ef56ab12cd34",
        schema_version=1,
        source_type=source_type,
        source_host=source_host,
        source_instance="clickhouse-itest-01",
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


def _packet_observation(observed_ns, src_ip, dst_ip, src_port, dst_port):
    return common_pb2.PacketObservation(
        observed_time_unix_nano=observed_ns,
        capture_direction=common_pb2.CAPTURE_DIRECTION_INGRESS,
        link=common_pb2.LinkLayerObservation(
            src_mac=CLIENT_MAC, dst_mac="ff:ff:ff:ff:ff:ff", ethertype=0x0800
        ),
        network=common_pb2.NetworkLayerObservation(
            protocol=common_pb2.NetworkLayerObservation.NETWORK_PROTOCOL_IPV4,
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
        ),
        packet_len=342,
        captured_len=342,
    )


def dns_transaction_service_role_event() -> CloudFlowEvent:
    """A fully-correlated client-facing DNS transaction WITH an operator-assigned
    service_role -- exercises the DNS row columns (qname/qtype/qclass/rcode/
    rtt_seconds/rtt_valid/role/service_role/client_ip/server_ip)."""
    query_ns = 1_730_000_002_000_000_000
    rtt_nanos = 1_234_567
    response_ns = query_ns + rtt_nanos

    envelope = _base_envelope(
        "dns",
        "dns.transaction.observed",
        query_ns,
        "cloudflow:v1:wire:dns",
        "dns-source-01.example.net",
        "cloudflow.v1.DnsTransactionEvent",
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
        header=dns_pb2.DnsHeader(id=0x1234, rd=True, qdcount=1), questions=[question]
    )
    response = dns_pb2.DnsMessage(
        header=dns_pb2.DnsHeader(id=0x1234, qr=True, rd=True, ra=True, rcode=0, qdcount=1, ancount=1),
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
        service_role="authoritative",
    )

    return CloudFlowEvent(envelope=envelope, dns_transaction=transaction)


def dhcpv4_discover_event() -> CloudFlowEvent:
    """A DHCPv4 DISCOVER (not relayed) -- exercises the DHCP row columns
    (message_type / client_key / is_relayed; requested/assigned absent)."""
    observed_ns = 1_730_000_000_123_456_789
    envelope = _base_envelope(
        "dhcpv4",
        "dhcpv4.discover.observed",
        observed_ns,
        "cloudflow:v1:wire:dhcpv4",
        "dhcp-source-01.example.net",
        "cloudflow.v1.DhcpV4PacketEvent",
    )

    header = dhcp_pb2.DhcpV4Header(
        op=1, htype=1, hlen=6, xid=0xDEADBEEF, flags=0x8000, chaddr_mac=CLIENT_MAC,
        magic_cookie_present=True,
    )
    decoded = dhcp_pb2.DhcpV4DecodedOptions(
        message_type=dhcp_pb2.DhcpV4DecodedOptions.DISCOVER, message_type_name="DISCOVER"
    )
    interpretation = dhcp_pb2.DhcpV4Interpretation(
        event_type="dhcpv4.discover.observed",
        transaction_key="deadbeef",
        normalized_client_key="02:00:00:00:00:01",
        is_relayed=False,
        is_broadcast=True,
    )

    packet_event = dhcp_pb2.DhcpV4PacketEvent(
        packet=_packet_observation(observed_ns, "198.51.100.10", "255.255.255.255", 68, 67),
        header=header,
        decoded=decoded,
        interpretation=interpretation,
    )
    return CloudFlowEvent(envelope=envelope, dhcpv4_packet=packet_event)


FIXTURES = {
    "dns_transaction_service_role": dns_transaction_service_role_event,
    "dhcpv4_discover": dhcpv4_discover_event,
}


def write_fixtures(outdir: Path) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    for name, build in FIXTURES.items():
        (outdir / f"{name}.pb").write_bytes(build().SerializeToString())
        print(f"wrote {outdir / (name + '.pb')}")


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    outdir = Path(argv[0]) if argv else (_HERE / "fixtures")
    write_fixtures(outdir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
