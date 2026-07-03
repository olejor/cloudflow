#!/usr/bin/env python3
"""Deterministic pcap fixture generator for the WP-06/WP-07 DHCP parsers.

Builds the DHCPv4 and DHCPv6 fixture corpus listed in
docs/design/02-packet-and-parsing.md ("Fixture corpus") into this directory:
one single-packet classic-pcap file plus a human-readable <name>.expected.md
per fixture. The v4_* builders (WP-06) and v6_* builders (WP-07) share the
same BUILDERS dict / main() loop and general conventions (fixed timestamp,
explicit fields, documentation address space) but each protocol has its own
byte-level helper functions -- nothing in the shared plumbing below is
protocol-specific.

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

from scapy.all import Dot1Q, Ether, IP, IPv6, Raw, UDP, wrpcap

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
# DHCPv6 address policy constants
#
# MACs continue the 02:00:5e:xx:xx:xx locally-administered range, with a
# distinct 0x20 third-octet-of-suffix band so v6 fixtures never collide with
# the v4 MACs above even though the two corpora are independent. Link-local
# addresses (fe80::/10) and the standard DHCPv6 multicast groups
# (ff02::1:2 "All_DHCP_Relay_Agents_and_Servers", ff02::1:3
# "All_DHCP_Servers") are protocol-mandated sentinel addresses, not policy
# picks -- the same way v4's ZERO_IP/BROADCAST_IP are -- so they are used
# where the DHCPv6 exchange itself requires them (RFC 8415 sections 5, 18);
# every other v6 address (assigned leases, relay link-address) comes from
# the 2001:db8::/32 documentation range (RFC 3849).
# ---------------------------------------------------------------------------

V6_CLIENT_MAC = "02:00:5e:20:00:01"
V6_SERVER_MAC = "02:00:5e:20:00:02"
V6_RELAY_MAC = "02:00:5e:20:00:0a"

V6_CLIENT_LL = "fe80::200:5eff:fe20:1"
V6_SERVER_LL = "fe80::200:5eff:fe20:2"
V6_RELAY_LL = "fe80::200:5eff:fe20:a"

ALL_DHCP_RELAY_AGENTS_AND_SERVERS = "ff02::1:2"
ALL_DHCP_SERVERS = "ff02::1:3"

V6_RELAY_LINK_ADDRESS = "2001:db8:1::1"
V6_SERVER_GLOBAL = "2001:db8:2::2"

V6_ASSIGNED_ADDRESS = "2001:db8::50"
V6_ASSIGNED_ADDRESS2 = "2001:db8::51"

V6_VENDOR_ENTERPRISE_NUMBER = 99999

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
# DHCPv6 byte-level helpers (independent of scapy's own DHCP6 layers, for the
# same "exactly and legibly what this script says" reason as the DHCPv4
# helpers above).
# ---------------------------------------------------------------------------


def ipv6(s):
    return socket.inet_pton(socket.AF_INET6, s)


def duid_ll(mac):
    """DUID-LL (RFC 8415 11.4): duid-type=3, hardware-type=1 (Ethernet),
    link-layer address. Deterministic from a MAC, per the fixture address
    policy."""
    return bytes([0, 3, 0, 1]) + mac_bytes(mac)


def dhcpv6_option(code, value):
    return u16(code) + u16(len(value)) + value


def encode_v6_options(opts):
    """opts: list of (code, value_bytes). Unlike DHCPv4, DHCPv6 options have
    no pad/end sentinel and no RFC 3396-style long-option split -- every
    option is just a 4-byte code/length header followed by its value."""
    out = b""
    for code, value in opts:
        out += dhcpv6_option(code, value)
    return out


def dhcpv6_client_server_payload(msg_type, xid, opts_bytes):
    assert 0 <= xid <= 0xFFFFFF
    return bytes([msg_type]) + xid.to_bytes(3, "big") + opts_bytes


def dhcpv6_relay_payload(msg_type, hop_count, link_address, peer_address, opts_bytes):
    return (bytes([msg_type, hop_count]) + ipv6(link_address) + ipv6(peer_address) +
            opts_bytes)


def build_ia_na(iaid, t1, t2, suboptions_bytes=b""):
    return u32(iaid) + u32(t1) + u32(t2) + suboptions_bytes


def build_iaaddr(address, preferred_lifetime, valid_lifetime, suboptions_bytes=b""):
    return ipv6(address) + u32(preferred_lifetime) + u32(valid_lifetime) + suboptions_bytes


def frame6(eth_src, eth_dst, ip6_src, ip6_dst, sport, dport, payload):
    """Wraps a raw DHCPv6 payload in Ethernet/IPv6/UDP via scapy, mirroring
    frame() above (every otherwise host-dependent/random field pinned
    explicitly, fixed capture timestamp)."""
    pkt = (Ether(src=eth_src, dst=eth_dst) /
           IPv6(src=ip6_src, dst=ip6_dst, hlim=64) /
           UDP(sport=sport, dport=dport) / Raw(load=payload))
    pkt.time = FIXED_TIME
    return pkt


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


def build_v6_solicit():
    xid = 0x101010
    client_duid = duid_ll(V6_CLIENT_MAC)
    oro = u16(23) + u16(24) + u16(31)  # DNS_SERVERS, DOMAIN_LIST, SNTP_SERVERS
    ia_na = build_ia_na(iaid=1, t1=0, t2=0)  # hint IA_NA, no IAADDR yet

    opts = encode_v6_options([
        (1, client_duid),  # OPTION_CLIENTID
        (6, oro),           # OPTION_ORO
        (3, ia_na),          # OPTION_IA_NA
    ])
    payload = dhcpv6_client_server_payload(1, xid, opts)  # SOLICIT
    pkt = frame6(V6_CLIENT_MAC, "33:33:00:01:00:02", V6_CLIENT_LL,
                 ALL_DHCP_RELAY_AGENTS_AND_SERVERS, 546, 547, payload)
    md = f"""# v6_solicit

SOLICIT with client DUID (1), ORO (6), and an IA_NA (3) hint (no IAADDR yet
-- the client does not have an address to request).

- msg-type=1 (SOLICIT), transaction_id=0x{xid:06x}
- decoded.client_duid = DUID-LL(3)/hwtype=Ethernet(1) over {V6_CLIENT_MAC}
- decoded.option_request_option_codes = [23, 24, 31]
- decoded.assigned_addresses is empty (the IA_NA carries no IAADDR)
- interpretation event_type = "dhcpv6.solicit.observed"
"""
    return pkt, md


def build_v6_advertise():
    xid = 0x101010  # same exchange as v6_solicit
    server_duid = duid_ll(V6_SERVER_MAC)
    client_duid = duid_ll(V6_CLIENT_MAC)
    iaaddr = build_iaaddr(V6_ASSIGNED_ADDRESS, 3600, 7200)
    ia_na = build_ia_na(iaid=1, t1=1800, t2=2880,
                         suboptions_bytes=encode_v6_options([(5, iaaddr)]))

    opts = encode_v6_options([
        (2, server_duid),  # OPTION_SERVERID
        (1, client_duid),   # OPTION_CLIENTID
        (3, ia_na),          # OPTION_IA_NA / IAADDR
    ])
    payload = dhcpv6_client_server_payload(2, xid, opts)  # ADVERTISE
    pkt = frame6(V6_SERVER_MAC, V6_CLIENT_MAC, V6_SERVER_LL, V6_CLIENT_LL, 547, 546, payload)
    md = f"""# v6_advertise

ADVERTISE (reply to v6_solicit) with an IA_NA containing one IAADDR.

- msg-type=2 (ADVERTISE), transaction_id=0x{xid:06x}
- decoded.server_duid = DUID-LL(3)/hwtype=Ethernet(1) over {V6_SERVER_MAC}
- decoded.client_duid = DUID-LL(3)/hwtype=Ethernet(1) over {V6_CLIENT_MAC}
- decoded.assigned_addresses = ["{V6_ASSIGNED_ADDRESS}"] (from IA_NA -> IAADDR)
- interpretation event_type = "dhcpv6.advertise.observed"
"""
    return pkt, md


def build_v6_request():
    xid = 0x202020
    client_duid = duid_ll(V6_CLIENT_MAC)
    server_duid = duid_ll(V6_SERVER_MAC)
    oro = u16(23) + u16(24)
    iaaddr = build_iaaddr(V6_ASSIGNED_ADDRESS, 3600, 7200)
    ia_na = build_ia_na(iaid=1, t1=1800, t2=2880,
                         suboptions_bytes=encode_v6_options([(5, iaaddr)]))

    opts = encode_v6_options([
        (1, client_duid),  # OPTION_CLIENTID
        (2, server_duid),   # OPTION_SERVERID (echoed from the ADVERTISE)
        (6, oro),            # OPTION_ORO
        (3, ia_na),           # OPTION_IA_NA (requesting the offered address)
    ])
    payload = dhcpv6_client_server_payload(3, xid, opts)  # REQUEST
    pkt = frame6(V6_CLIENT_MAC, "33:33:00:01:00:02", V6_CLIENT_LL,
                 ALL_DHCP_RELAY_AGENTS_AND_SERVERS, 546, 547, payload)
    md = f"""# v6_request

REQUEST carrying client DUID, the server DUID echoed from v6_advertise, ORO,
and an IA_NA requesting the offered address.

- msg-type=3 (REQUEST), transaction_id=0x{xid:06x}
- decoded.client_duid / decoded.server_duid both present
- decoded.option_request_option_codes = [23, 24]
- decoded.assigned_addresses = ["{V6_ASSIGNED_ADDRESS}"]
- interpretation event_type = "dhcpv6.request.observed"
"""
    return pkt, md


def build_v6_reply():
    xid = 0x202020  # same exchange as v6_request
    server_duid = duid_ll(V6_SERVER_MAC)
    client_duid = duid_ll(V6_CLIENT_MAC)
    iaaddr = build_iaaddr(V6_ASSIGNED_ADDRESS, 3600, 7200)
    ia_na = build_ia_na(iaid=1, t1=1800, t2=2880,
                         suboptions_bytes=encode_v6_options([(5, iaaddr)]))

    opts = encode_v6_options([
        (2, server_duid),  # OPTION_SERVERID
        (1, client_duid),   # OPTION_CLIENTID
        (3, ia_na),          # OPTION_IA_NA / IAADDR (assigned address)
    ])
    payload = dhcpv6_client_server_payload(7, xid, opts)  # REPLY
    pkt = frame6(V6_SERVER_MAC, V6_CLIENT_MAC, V6_SERVER_LL, V6_CLIENT_LL, 547, 546, payload)
    md = f"""# v6_reply

REPLY (reply to v6_request) with the assigned address and server DUID.

- msg-type=7 (REPLY), transaction_id=0x{xid:06x}
- decoded.server_duid = DUID-LL(3)/hwtype=Ethernet(1) over {V6_SERVER_MAC}
- decoded.assigned_addresses = ["{V6_ASSIGNED_ADDRESS}"]
- interpretation event_type = "dhcpv6.reply.observed"
"""
    return pkt, md


def build_v6_relay_forw():
    # Inner message: a standalone SOLICIT (independent xid/content from
    # v6_solicit -- this fixture is self-contained), carried verbatim as the
    # Relay Message option's (9) raw bytes; v0.1 does not recursively parse
    # it (docs/design/02-packet-and-parsing.md's WP-07 section).
    inner_xid = 0x303030
    inner_client_duid = duid_ll(V6_CLIENT_MAC)
    inner_oro = u16(23) + u16(24) + u16(31)
    inner_ia_na = build_ia_na(iaid=1, t1=0, t2=0)
    inner_opts = encode_v6_options([
        (1, inner_client_duid),
        (6, inner_oro),
        (3, inner_ia_na),
    ])
    inner_payload = dhcpv6_client_server_payload(1, inner_xid, inner_opts)  # SOLICIT

    interface_id = b"eth0"
    outer_opts = encode_v6_options([
        (9, inner_payload),   # OPTION_RELAY_MSG
        (18, interface_id),    # OPTION_INTERFACE_ID
    ])
    payload = dhcpv6_relay_payload(12, 0, V6_RELAY_LINK_ADDRESS, V6_CLIENT_LL, outer_opts)
    pkt = frame6(V6_RELAY_MAC, "33:33:00:01:00:03", V6_RELAY_LINK_ADDRESS,
                 ALL_DHCP_SERVERS, 547, 547, payload)
    md = f"""# v6_relay_forw

RELAY-FORW wrapping a SOLICIT: hop-count/link-address/peer-address in the
outer header, plus an OPTION_RELAY_MSG (9) outer option carrying the inner
SOLICIT's raw bytes verbatim (not recursively parsed in v0.1) and an
OPTION_INTERFACE_ID (18) outer option.

- msg-type=12 (RELAY-FORW), hop_count=0
- header.link_address = "{V6_RELAY_LINK_ADDRESS}"
- header.peer_address = "{V6_CLIENT_LL}"
- raw_options includes code=9 (OPTION_RELAY_MSG) whose raw_value is exactly
  the inner SOLICIT's {len(inner_payload)} bytes
  (msg-type=1, transaction_id=0x{inner_xid:06x})
- raw_options includes code=18 (OPTION_INTERFACE_ID), raw_value = b"eth0"
- decoded.* fields reflect only the *outer* options (empty/default here --
  the outer message carries no DUID/IA_NA/ORO of its own)
- interpretation event_type = "dhcpv6.relay-forw.observed"
"""
    return pkt, md


def build_v6_vendor_opts():
    xid = 0x404040
    client_duid = duid_ll(V6_CLIENT_MAC)
    vendor_suboptions = encode_v6_options([
        (1, b"cloudflow-fixture"),          # printable -> decoded as text
        (2, bytes([0xDE, 0xAD, 0xBE, 0xEF])),  # binary -> decoded as hex
    ])
    vendor_opts_value = u32(V6_VENDOR_ENTERPRISE_NUMBER) + vendor_suboptions

    opts = encode_v6_options([
        (1, client_duid),    # OPTION_CLIENTID
        (17, vendor_opts_value),  # OPTION_VENDOR_OPTS
    ])
    payload = dhcpv6_client_server_payload(11, xid, opts)  # INFORMATION-REQUEST
    pkt = frame6(V6_CLIENT_MAC, "33:33:00:01:00:02", V6_CLIENT_LL,
                 ALL_DHCP_RELAY_AGENTS_AND_SERVERS, 546, 547, payload)
    md = f"""# v6_vendor_opts

INFORMATION-REQUEST carrying option 17 (vendor-specific information) with an
enterprise number and two suboptions (one printable, one binary).

- msg-type=11 (INFORMATION-REQUEST), transaction_id=0x{xid:06x}
- decoded.vendor_options.enterprise_number = {V6_VENDOR_ENTERPRISE_NUMBER}
- decoded.vendor_options.suboptions[0]: code=1, decoded_value="cloudflow-fixture"
- decoded.vendor_options.suboptions[1]: code=2, raw_value=de:ad:be:ef (hex, not printable)
- interpretation event_type = "dhcpv6.information-request.observed"
"""
    return pkt, md


def build_v6_malformed_optlen():
    xid = 0x505050
    client_duid = duid_ll(V6_CLIENT_MAC)

    # Hand-built (not via encode_v6_options, which would refuse to lie about
    # a length): a well-formed OPTION_CLIENTID (1), then an OPTION_ORO (6)
    # that declares a 4-byte value but the payload ends after only 1 of
    # those bytes -- no further options. This is the "option length
    # overruns payload" case.
    opts_bytes = dhcpv6_option(1, client_duid) + u16(6) + u16(4) + bytes([0x00])
    payload = dhcpv6_client_server_payload(1, xid, opts_bytes)  # SOLICIT
    pkt = frame6(V6_CLIENT_MAC, "33:33:00:01:00:02", V6_CLIENT_LL,
                 ALL_DHCP_RELAY_AGENTS_AND_SERVERS, 546, 547, payload)
    md = f"""# v6_malformed_optlen

Hand-built (not scapy-encoded) payload: a valid OPTION_CLIENTID (1) followed
by an OPTION_ORO (6) that declares a 4-byte value but the payload ends after
only 1 of those bytes, with no further options. Exercises the "never trust
lengths" / best-resync requirement.

- msg-type=1 (SOLICIT), transaction_id=0x{xid:06x}
- Parsing succeeds (non-NULL event) despite the malformed trailing option.
- decoded.client_duid is still recovered (option 1 came first and was intact)
- raw_options' last entry: code=6, malformed=true, length=1
- parser_warnings is non-empty and includes a warning with
  code="opt_len_overrun" and field_path="raw_options[1]"
- interpretation event_type = "dhcpv6.solicit.observed"
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
    "v6_solicit": build_v6_solicit,
    "v6_advertise": build_v6_advertise,
    "v6_request": build_v6_request,
    "v6_reply": build_v6_reply,
    "v6_relay_forw": build_v6_relay_forw,
    "v6_vendor_opts": build_v6_vendor_opts,
    "v6_malformed_optlen": build_v6_malformed_optlen,
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
