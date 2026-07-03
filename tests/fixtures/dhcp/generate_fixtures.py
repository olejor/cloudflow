#!/usr/bin/env python3
"""Deterministic pcap fixture generator for the WP-06/WP-07 DHCP parsers.

Builds the DHCPv4 fixture corpus listed in docs/design/02-packet-and-parsing.md
("Fixture corpus") into this directory: one single-packet classic-pcap file
plus a human-readable <name>.expected.md per fixture. WP-07 will add v6
builders to the same BUILDERS dict / main() loop -- nothing here is
DHCPv4-specific except the builder functions themselves and the DHCPv4 byte
helpers they call.

Determinism (required so `python3 generate_fixtures.py` is a no-op on a
clean checkout -- see the "Re-run must produce byte-identical files"
acceptance criterion):
  - every address/MAC is a literal constant from the address policy below,
    never resolved from the host's routing table or interfaces;
  - every scapy packet's `.time` is pinned to FIXED_TIME (a fixed Unix
    epoch, not wall-clock `time.time()`), so the pcap per-packet header's
    timestamp never changes between runs;
  - every scapy layer that scapy would otherwise fill from a "random by
    default" or host-dependent field (IP.id, Ether without explicit
    src/dst) has that field set explicitly;
  - v4_malformed_optlen's DHCP payload is assembled by hand (see
    build_v4_malformed_optlen) instead of through scapy's DHCP layer,
    because scapy recomputes/validates option lengths and would silently
    "fix" the deliberately-wrong length this fixture needs.

Address policy (docs/design/02-packet-and-parsing.md): IPv4 addresses only
from 192.0.2.0/24 and 198.51.100.0/24 (RFC 5737 documentation ranges), MACs
only from 02:00:5e:xx:xx:xx (locally administered).

Usage:
    python3 tests/fixtures/dhcp/generate_fixtures.py
Regenerates every fixture in this directory. The .pcap/.expected.md outputs
are committed to the repo (per the WP-06 task); this script is what
produced them and is the tool to re-run after intentionally changing a
fixture's content.
"""

import os
import socket
import struct

from scapy.all import Dot1Q, Ether, IP, Raw, UDP, wrpcap

FIXED_TIME = 1700000000.0  # 2023-11-14T22:13:20Z, arbitrary and fixed.

OUT_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# Address policy constants
# ---------------------------------------------------------------------------

CLIENT_MAC = "02:00:5e:10:00:01"
SERVER_MAC = "02:00:5e:10:00:02"
RELAY_MAC = "02:00:5e:10:00:0a"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

SERVER_IP = "192.0.2.2"
ROUTER_IP = "192.0.2.1"
DNS1_IP = "192.0.2.53"
DNS2_IP = "198.51.100.53"
SUBNET_MASK = "255.255.255.0"
OFFERED_IP = "192.0.2.50"
RENEWAL_CIADDR = "192.0.2.51"
BROADCAST_IP = "255.255.255.255"
ZERO_IP = "0.0.0.0"

RELAY_GIADDR = "198.51.100.1"
RELAYED_CLIENT_IP = "198.51.100.50"

DOMAIN_NAME = "example.com"
CLIENT_FQDN = "client1.example.com"

# ---------------------------------------------------------------------------
# DHCPv4 byte-level helpers (independent of scapy's own DHCP/BOOTP layers --
# built by hand so every fixture's wire bytes are exactly and legibly what
# this script says they are, including the one fixture that must be
# deliberately malformed).
# ---------------------------------------------------------------------------

MAGIC_COOKIE = bytes([99, 130, 83, 99])


def mac_bytes(s):
    return bytes(int(x, 16) for x in s.split(":"))


def u16(v):
    return struct.pack("!H", v)


def u32(v):
    return struct.pack("!I", v)


def ipv4(s):
    return socket.inet_aton(s)


def bootp_fixed(op, htype, hlen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr,
                 giaddr, chaddr, sname=b"", file=b""):
    chaddr16 = (chaddr + b"\x00" * 16)[:16]
    sname64 = (sname + b"\x00" * 64)[:64]
    file128 = (file + b"\x00" * 128)[:128]
    hdr = bytes([op, htype, hlen, hops]) + u32(xid) + u16(secs) + u16(flags)
    hdr += ipv4(ciaddr) + ipv4(yiaddr) + ipv4(siaddr) + ipv4(giaddr)
    hdr += chaddr16 + sname64 + file128
    assert len(hdr) == 236
    return hdr


def encode_options(opts):
    """opts: list of (code, value_bytes). code 0 -> a single pad byte
    (value ignored); code 255 -> a single end byte (value ignored). Values
    longer than 255 bytes are RFC 3396 split into consecutive same-code
    fragments automatically (the split point is a plain byte-count cut,
    which is all RFC 3396 requires -- it does not need to land on any
    logical sub-structure boundary)."""
    out = b""
    for code, value in opts:
        if code == 0:
            out += bytes([0])
        elif code == 255:
            out += bytes([255])
        elif len(value) == 0:
            out += bytes([code, 0])
        else:
            for i in range(0, len(value), 255):
                chunk = value[i:i + 255]
                out += bytes([code, len(chunk)]) + chunk
    return out


def dhcp_payload(fixed, opts):
    return fixed + MAGIC_COOKIE + encode_options(opts)


def frame(eth_src, eth_dst, ip_src, ip_dst, sport, dport, payload, vlan=None):
    """Wraps a raw DHCP payload in Ethernet[/802.1Q]/IPv4/UDP via scapy,
    with every field that could otherwise be host-dependent or random
    pinned explicitly, and a fixed capture timestamp."""
    l2 = Ether(src=eth_src, dst=eth_dst)
    if vlan is not None:
        l2 = l2 / Dot1Q(vlan=vlan)
    pkt = l2 / IP(src=ip_src, dst=ip_dst, id=0, ttl=64) / \
        UDP(sport=sport, dport=dport) / Raw(load=payload)
    pkt.time = FIXED_TIME
    return pkt


def classless_routes_bytes(entries):
    """entries: list of (prefix_len, dest_octets_bytes, router_ipv4_str)."""
    out = b""
    for prefix_len, dest_bytes, router in entries:
        out += bytes([prefix_len]) + dest_bytes + ipv4(router)
    return out


def domain_labels(*labels):
    out = b""
    for label in labels:
        out += bytes([len(label)]) + label.encode("ascii")
    return out


# ---------------------------------------------------------------------------
# Fixture builders. Each returns (scapy_packet, expected_md_body).
# ---------------------------------------------------------------------------


def build_v4_discover():
    xid = 0x11111111
    fixed = bootp_fixed(op=1, htype=1, hlen=6, hops=0, xid=xid, secs=0,
                         flags=0x8000, ciaddr=ZERO_IP, yiaddr=ZERO_IP,
                         siaddr=ZERO_IP, giaddr=ZERO_IP, chaddr=mac_bytes(CLIENT_MAC))
    opts = [
        (53, bytes([1])),                       # DHCPDISCOVER
        (55, bytes([1, 3, 6, 15])),              # parameter request list
        (57, u16(1500)),                         # max message size
        (61, bytes([1]) + mac_bytes(CLIENT_MAC)),  # client id (type 1 + MAC)
        (255, b""),
    ]
    payload = dhcp_payload(fixed, opts)
    pkt = frame(CLIENT_MAC, BROADCAST_MAC, ZERO_IP, BROADCAST_IP, 68, 67, payload)
    md = f"""# v4_discover

Basic DHCPDISCOVER, exercising options 53/55/57/61.

- xid: 0x{xid:08x}
- op=1 (BOOTREQUEST), htype=1, hlen=6, flags=0x8000 (broadcast)
- ciaddr=yiaddr=siaddr=giaddr={ZERO_IP}
- chaddr -> chaddr_mac = {CLIENT_MAC}
- decoded.message_type = DISCOVER, message_type_name = "DISCOVER"
- decoded.parameter_request_list = [1, 3, 6, 15]
- decoded.max_dhcp_message_size = 1500
- decoded.client_identifier_raw = 01:{CLIENT_MAC.replace(':', '')}, client_identifier_text = "{CLIENT_MAC}"
- interpretation.event_type = "dhcpv4.discover.observed"
- interpretation.is_broadcast = true
- interpretation.is_relayed = false
- interpretation.normalized_client_key = client-id hex ("01" + MAC hex)
"""
    return pkt, md


def build_v4_offer():
    xid = 0x11111111
    fixed = bootp_fixed(op=2, htype=1, hlen=6, hops=0, xid=xid, secs=0,
                         flags=0x8000, ciaddr=ZERO_IP, yiaddr=OFFERED_IP,
                         siaddr=SERVER_IP, giaddr=ZERO_IP, chaddr=mac_bytes(CLIENT_MAC))
    opts = [
        (53, bytes([2])),                        # DHCPOFFER
        (1, ipv4(SUBNET_MASK)),
        (3, ipv4(ROUTER_IP)),
        (6, ipv4(DNS1_IP) + ipv4(DNS2_IP)),
        (51, u32(86400)),
        (54, ipv4(SERVER_IP)),
        (58, u32(43200)),
        (59, u32(75600)),
        (255, b""),
    ]
    payload = dhcp_payload(fixed, opts)
    pkt = frame(SERVER_MAC, BROADCAST_MAC, SERVER_IP, BROADCAST_IP, 67, 68, payload)
    md = f"""# v4_offer

DHCPOFFER with subnet mask, router, two DNS servers, lease time, T1, T2.

- xid: 0x{xid:08x}
- op=2 (BOOTREPLY), yiaddr={OFFERED_IP}, siaddr={SERVER_IP}
- decoded.message_type = OFFER
- decoded.subnet_mask = {SUBNET_MASK}
- decoded.routers = [{ROUTER_IP}]
- decoded.domain_name_servers = [{DNS1_IP}, {DNS2_IP}]
- decoded.ip_address_lease_time_seconds = 86400
- decoded.server_identifier = {SERVER_IP}
- decoded.renewal_time_t1_seconds = 43200
- decoded.rebinding_time_t2_seconds = 75600
- interpretation.event_type = "dhcpv4.offer.observed"
- interpretation.lease_address = "{OFFERED_IP}" (yiaddr, since message type is OFFER)
"""
    return pkt, md


def build_v4_request_renewal():
    xid = 0x33333333
    fixed = bootp_fixed(op=1, htype=1, hlen=6, hops=0, xid=xid, secs=0,
                         flags=0x0000, ciaddr=RENEWAL_CIADDR, yiaddr=ZERO_IP,
                         siaddr=ZERO_IP, giaddr=ZERO_IP, chaddr=mac_bytes(CLIENT_MAC))
    opts = [
        (53, bytes([3])),                        # DHCPREQUEST
        (55, bytes([1, 3, 6, 15])),
        (255, b""),
    ]
    payload = dhcp_payload(fixed, opts)
    pkt = frame(CLIENT_MAC, SERVER_MAC, RENEWAL_CIADDR, SERVER_IP, 68, 67, payload)
    md = f"""# v4_request_renewal

Unicast DHCPREQUEST with no requested-ip (50) and no server-id (54) option
-- the renewal heuristic (see cf_dhcpv4.c's build_interpretation comment):
a REQUEST missing both of those, sent unicast (broadcast flag clear), is
classified as a lease renewal (RENEWING state per RFC 2131) rather than a
rebind.

- xid: 0x{xid:08x}
- op=1, ciaddr={RENEWAL_CIADDR} (the lease being renewed), flags=0x0000 (unicast)
- decoded.message_type = REQUEST
- decoded.requested_ip_address = "" (absent)
- decoded.server_identifier = "" (absent)
- interpretation.event_type = "dhcpv4.request.observed"
- interpretation.is_broadcast = false
- interpretation.is_renewal = true
- interpretation.is_rebind = false
"""
    return pkt, md


def build_v4_ack():
    xid = 0x33333333
    fixed = bootp_fixed(op=2, htype=1, hlen=6, hops=0, xid=xid, secs=0,
                         flags=0x0000, ciaddr=ZERO_IP, yiaddr=RENEWAL_CIADDR,
                         siaddr=SERVER_IP, giaddr=ZERO_IP, chaddr=mac_bytes(CLIENT_MAC))

    # option 81: client FQDN, wire-format (E bit set) encoding of
    # "client1.example.com".
    fqdn_name = domain_labels("client1", "example", "com") + bytes([0])
    fqdn = bytes([0x04, 0x00, 0x00]) + fqdn_name

    # option 119: domain search list ["eng.example.com", "example.com"],
    # RFC 1035 compressed -- the second name is a pointer back into the
    # first name's "example.com" suffix, entirely within this option's own
    # (concatenated) bytes.
    first = domain_labels("eng", "example", "com") + bytes([0])
    off_example = 1 + len("eng")  # offset of the "example" label in `first`
    ds = first + bytes([0xC0, off_example])

    opts = [
        (53, bytes([5])),                        # DHCPACK
        (1, ipv4(SUBNET_MASK)),
        (51, u32(86400)),
        (54, ipv4(SERVER_IP)),
        (58, u32(43200)),
        (59, u32(75600)),
        (81, fqdn),
        (119, ds),
        (255, b""),
    ]
    payload = dhcp_payload(fixed, opts)
    pkt = frame(SERVER_MAC, CLIENT_MAC, SERVER_IP, RENEWAL_CIADDR, 67, 68, payload)
    md = f"""# v4_ack

DHCPACK (reply to v4_request_renewal's REQUEST) carrying option 81 (client
FQDN, wire/RFC 1035-label encoding) and option 119 (domain search list,
RFC 1035 compressed within the option's own concatenated bytes).

- xid: 0x{xid:08x}
- op=2, yiaddr={RENEWAL_CIADDR}, siaddr={SERVER_IP}
- decoded.message_type = ACK
- decoded.client_fqdn.flags = 0x04 (E bit set: wire-format encoding)
- decoded.client_fqdn.domain_name = "{CLIENT_FQDN}"
- decoded.domain_search = ["eng.{DOMAIN_NAME}", "{DOMAIN_NAME}"]
  (the second name is a compression pointer back into the first)
- interpretation.event_type = "dhcpv4.ack.observed"
- interpretation.lease_address = "{RENEWAL_CIADDR}"
"""
    return pkt, md


def build_v4_nak():
    xid = 0x44444444
    fixed = bootp_fixed(op=2, htype=1, hlen=6, hops=0, xid=xid, secs=0,
                         flags=0x8000, ciaddr=ZERO_IP, yiaddr=ZERO_IP,
                         siaddr=SERVER_IP, giaddr=ZERO_IP, chaddr=mac_bytes(CLIENT_MAC))
    message = b"requested address not available on this subnet"
    opts = [
        (53, bytes([6])),                        # DHCPNAK
        (54, ipv4(SERVER_IP)),
        (56, message),
        (255, b""),
    ]
    payload = dhcp_payload(fixed, opts)
    pkt = frame(SERVER_MAC, BROADCAST_MAC, SERVER_IP, BROADCAST_IP, 67, 68, payload)
    md = f"""# v4_nak

DHCPNAK carrying option 56 (message).

- xid: 0x{xid:08x}
- op=2, yiaddr={ZERO_IP} (NAK never carries a lease address)
- decoded.message_type = NAK
- decoded.server_identifier = {SERVER_IP}
- decoded.message = "{message.decode('ascii')}"
- interpretation.event_type = "dhcpv4.nak.observed"
- interpretation.lease_address = "" (NAK is not OFFER/ACK)
"""
    return pkt, md


def build_v4_relayed_ack():
    xid = 0x55555555
    fixed = bootp_fixed(op=2, htype=1, hlen=6, hops=1, xid=xid, secs=0,
                         flags=0x0000, ciaddr=ZERO_IP, yiaddr=RELAYED_CLIENT_IP,
                         siaddr=SERVER_IP, giaddr=RELAY_GIADDR,
                         chaddr=mac_bytes(CLIENT_MAC))

    circuit_id = b"eth01"                # printable -> decoded as text
    remote_id = mac_bytes(RELAY_MAC)     # binary -> decoded as hex
    subscriber_id = b"sub-001"           # printable -> decoded as text
    relay_info = (bytes([1, len(circuit_id)]) + circuit_id +
                  bytes([2, len(remote_id)]) + remote_id +
                  bytes([6, len(subscriber_id)]) + subscriber_id)

    opts = [
        (53, bytes([5])),                        # DHCPACK
        (51, u32(43200)),
        (54, ipv4(SERVER_IP)),
        (82, relay_info),
        (255, b""),
    ]
    payload = dhcp_payload(fixed, opts)
    # Relayed traffic: server unicasts the reply to the relay agent's own
    # address (giaddr), port 67 both ends.
    pkt = frame(SERVER_MAC, RELAY_MAC, SERVER_IP, RELAY_GIADDR, 67, 67, payload)
    md = f"""# v4_relayed_ack

DHCPACK forwarded through a relay agent: giaddr set, option 82 (relay agent
information) with circuit-id, remote-id, and subscriber-id suboptions.

- xid: 0x{xid:08x}
- op=2, hops=1, giaddr={RELAY_GIADDR}, yiaddr={RELAYED_CLIENT_IP}
- decoded.message_type = ACK
- decoded.relay_agent_information.circuit_id = "eth01" (option 1, printable -> text)
- decoded.relay_agent_information.remote_id = hex("{RELAY_MAC}") (option 2, binary MAC -> hex)
- decoded.relay_agent_information.subscriber_id = "sub-001" (option 6, printable -> text)
- interpretation.event_type = "dhcpv4.ack.observed"
- interpretation.is_relayed = true
"""
    return pkt, md


def build_v4_vlan_discover():
    xid = 0x66666666
    fixed = bootp_fixed(op=1, htype=1, hlen=6, hops=0, xid=xid, secs=0,
                         flags=0x8000, ciaddr=ZERO_IP, yiaddr=ZERO_IP,
                         siaddr=ZERO_IP, giaddr=ZERO_IP, chaddr=mac_bytes(CLIENT_MAC))
    opts = [
        (53, bytes([1])),
        (55, bytes([1, 3, 6, 15])),
        (61, bytes([1]) + mac_bytes(CLIENT_MAC)),
        (255, b""),
    ]
    payload = dhcp_payload(fixed, opts)
    pkt = frame(CLIENT_MAC, BROADCAST_MAC, ZERO_IP, BROADCAST_IP, 68, 67, payload,
                vlan=100)
    md = f"""# v4_vlan_discover

Same DHCPDISCOVER as v4_discover, but 802.1Q tagged (VLAN 100) -- exercises
WP-05's cf_decap VLAN handling as well as the WP-06 parser; the DHCPv4
fields themselves are unaffected by the VLAN tag (cf_decap strips it before
cf_dhcpv4_parse ever sees the payload).

- VLAN id: 100
- xid: 0x{xid:08x}
- decoded.message_type = DISCOVER
- interpretation.event_type = "dhcpv4.discover.observed"
"""
    return pkt, md


def build_v4_overload():
    xid = 0x77777777
    fixed = bootp_fixed(op=2, htype=1, hlen=6, hops=0, xid=xid, secs=0,
                         flags=0x0000, ciaddr=ZERO_IP, yiaddr=OFFERED_IP,
                         siaddr=SERVER_IP, giaddr=ZERO_IP, chaddr=mac_bytes(CLIENT_MAC))

    primary_opts = encode_options([
        (53, bytes([5])),   # DHCPACK
        (52, bytes([3])),   # overload: both file and sname carry options
        (255, b""),
    ])

    file_opts = encode_options([
        (1, ipv4(SUBNET_MASK)),
        (3, ipv4(ROUTER_IP)),
        (255, b""),
    ])
    file_field = (file_opts + b"\x00" * 128)[:128]

    sname_opts = encode_options([
        (6, ipv4(DNS1_IP)),
        (12, b"host1"),
        (255, b""),
    ])
    sname_field = (sname_opts + b"\x00" * 64)[:64]

    payload = (fixed[:44] + sname_field + file_field + MAGIC_COOKIE + primary_opts)
    assert len(payload) == 236 + 4 + len(primary_opts)
    pkt = frame(SERVER_MAC, CLIENT_MAC, SERVER_IP, OFFERED_IP, 67, 68, payload)
    md = f"""# v4_overload

DHCPACK using option 52 (overload = 3): the primary options field only
carries options 53 and 52; the "file" field carries options 1 (subnet mask)
and 3 (router), and the "sname" field carries options 6 (DNS) and 12
(hostname).

- xid: 0x{xid:08x}
- decoded.option_overload = 3
- decoded.subnet_mask = {SUBNET_MASK} (recovered from the "file" field)
- decoded.routers = [{ROUTER_IP}] (recovered from the "file" field)
- decoded.domain_name_servers = [{DNS1_IP}] (recovered from the "sname" field)
- decoded.host_name = "host1" (recovered from the "sname" field)
- raw_options includes entries with source_field = SOURCE_FIELD_FILE and
  SOURCE_FIELD_SNAME in addition to SOURCE_FIELD_OPTIONS
- header.sname_text / header.file_text are both empty: their bytes are
  option TLVs (control-byte option codes), not printable ASCII text
"""
    return pkt, md


def build_v4_long_option():
    xid = 0x88888888
    fixed = bootp_fixed(op=2, htype=1, hlen=6, hops=0, xid=xid, secs=0,
                         flags=0x0000, ciaddr=ZERO_IP, yiaddr=ZERO_IP,
                         siaddr=SERVER_IP, giaddr=ZERO_IP, chaddr=mac_bytes(CLIENT_MAC))

    n_routes = 40
    entries = []
    for i in range(n_routes):
        dest = bytes([192, 0, 2, i])  # 192.0.2.<i>/32, all within 192.0.2.0/24
        entries.append((32, dest, "198.51.100.1"))
    csr = classless_routes_bytes(entries)
    assert len(csr) == n_routes * 9 == 360  # > 255 -> forces an RFC 3396 split

    opts = [
        (53, bytes([5])),   # DHCPACK
        (121, csr),
        (255, b""),
    ]
    payload = dhcp_payload(fixed, opts)
    pkt = frame(SERVER_MAC, CLIENT_MAC, SERVER_IP, ZERO_IP, 67, 68, payload)
    md = f"""# v4_long_option

DHCPACK with option 121 (classless static routes) long enough (360 bytes)
to require an RFC 3396 split into two consecutive option-121 instances
(255 + 105 bytes) in raw_options; decoding must concatenate them before
parsing route entries.

- xid: 0x{xid:08x}
- raw_options has exactly 2 entries with code == 121, both with
  source_field = SOURCE_FIELD_OPTIONS and long_option_fragment = true
- decoded.classless_static_routes has {n_routes} entries:
  - [0]: destination_prefix_length=32, destination="192.0.2.0", router="198.51.100.1"
  - [{n_routes - 1}]: destination_prefix_length=32, destination="192.0.2.{n_routes - 1}", router="198.51.100.1"
"""
    return pkt, md


def build_v4_malformed_optlen():
    xid = 0x99999999
    fixed = bootp_fixed(op=1, htype=1, hlen=6, hops=0, xid=xid, secs=0,
                         flags=0x0000, ciaddr=ZERO_IP, yiaddr=ZERO_IP,
                         siaddr=ZERO_IP, giaddr=ZERO_IP, chaddr=mac_bytes(CLIENT_MAC))

    # Hand-built (not via encode_options, which would refuse to lie about a
    # length): a well-formed option 53 (message type = DISCOVER), then
    # option 50 (requested IP) claiming a 4-byte value but with only 1 byte
    # actually present before the payload just ends -- no end marker, no
    # further options. This is the "option length overruns payload" case.
    opts_bytes = bytes([53, 1, 1]) + bytes([50, 4, 0xAA])
    payload = fixed + MAGIC_COOKIE + opts_bytes
    pkt = frame(CLIENT_MAC, BROADCAST_MAC, ZERO_IP, BROADCAST_IP, 68, 67, payload)
    md = f"""# v4_malformed_optlen

Hand-built (not scapy-encoded) payload: a valid option 53 (DISCOVER)
followed by an option 50 (requested IP) that declares a 4-byte value but
the payload ends after only 1 of those bytes, with no end marker. Exercises
the "never trust lengths" / best-resync requirement.

- xid: 0x{xid:08x}
- Parsing succeeds (non-NULL event) despite the malformed trailing option.
- decoded.message_type = DISCOVER (recovered -- option 53 came first and
  was intact)
- raw_options' last entry: code=50, malformed=true, raw_value = the single
  available byte (0xAA), length=1
- parser_warnings is non-empty and includes a warning with
  code="opt_len_overrun" and field_path="raw_options[1]"
- interpretation.event_type = "dhcpv4.discover.observed"
"""
    return pkt, md


def build_v4_no_msgtype():
    xid = 0xAAAAAAAA
    fixed = bootp_fixed(op=1, htype=1, hlen=6, hops=0, xid=xid, secs=0,
                         flags=0x0000, ciaddr=ZERO_IP, yiaddr=ZERO_IP,
                         siaddr=ZERO_IP, giaddr=ZERO_IP, chaddr=mac_bytes(CLIENT_MAC))
    opts = [
        (61, bytes([1]) + mac_bytes(CLIENT_MAC)),
        (255, b""),
    ]
    payload = dhcp_payload(fixed, opts)
    pkt = frame(CLIENT_MAC, BROADCAST_MAC, ZERO_IP, BROADCAST_IP, 68, 67, payload)
    md = f"""# v4_no_msgtype

BOOTP-ish packet (valid magic cookie and one ordinary option) but with no
option 53 (message type) at all.

- xid: 0x{xid:08x}
- decoded.message_type = MESSAGE_TYPE_UNSPECIFIED, message_type_name = ""
- interpretation.event_type = "dhcpv4.packet.observed"
"""
    return pkt, md


BUILDERS = {
    "v4_discover": build_v4_discover,
    "v4_offer": build_v4_offer,
    "v4_request_renewal": build_v4_request_renewal,
    "v4_ack": build_v4_ack,
    "v4_nak": build_v4_nak,
    "v4_relayed_ack": build_v4_relayed_ack,
    "v4_vlan_discover": build_v4_vlan_discover,
    "v4_overload": build_v4_overload,
    "v4_long_option": build_v4_long_option,
    "v4_malformed_optlen": build_v4_malformed_optlen,
    "v4_no_msgtype": build_v4_no_msgtype,
    # WP-07 adds v6_* builders here.
}


def main():
    for name, builder in BUILDERS.items():
        pkt, md_body = builder()
        pcap_path = os.path.join(OUT_DIR, f"{name}.pcap")
        md_path = os.path.join(OUT_DIR, f"{name}.expected.md")

        wrpcap(pcap_path, [pkt])

        with open(md_path, "w") as f:
            f.write(md_body)

        print(f"wrote {pcap_path} and {md_path}")


if __name__ == "__main__":
    main()
