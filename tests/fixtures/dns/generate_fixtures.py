#!/usr/bin/env python3
"""Deterministic pcap fixture generator for the WP-DNS03 parser / WP-DNS09
fuzz corpus.

Builds the sanitized DNS fixture corpus described in docs/dns-source.md
("Fixture and test policy") into this directory: one single-packet
classic-pcap file per fixture. The corpus is deliberately built as
query+response PAIRS (same DNS id, endpoints swapped) so the correlation
stage (WP-DNS04) can be driven end to end offline via the replay path, plus
a couple of deliberately malformed single messages for WP-DNS09's
never-crash / never-leak sweep.

Every DNS message body is assembled by hand from the byte-level helpers
below (not through scapy's DNS layer) so the wire bytes -- including
RFC 1035 name compression pointers and the deliberately-malformed cases
(truncated message, self-referential compression loop) -- are exactly and
legibly what this script says they are; scapy's DNS layer would "fix" or
refuse to emit several of these.

Determinism (required so re-running is a no-op on a clean checkout, mirroring
tests/fixtures/dhcp/generate_fixtures.py):
  - every address is a literal constant from the address policy below, never
    resolved from the host;
  - every DNS id and UDP/TCP port is a fixed literal, so message bytes are
    byte-stable;
  - every scapy packet's `.time` is pinned to FIXED_TIME, and every layer
    field scapy would otherwise randomize/host-derive (IP.id, Ether src/dst,
    TCP seq/ack/flags/window) is set explicitly.

Address policy (docs/dns-source.md): IPv4 only from 192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24 (RFC 5737 documentation ranges); IPv6 only
from 2001:db8::/32 (RFC 3849); domain names only under example.com
(RFC 2606 / documentation). MACs from 02:00:5e:xx:xx:xx (locally
administered), continuing a distinct 0x30 band so the DNS MACs never collide
with the DHCP v4 (0x10) / v6 (0x20) fixture MACs.

Usage:
    python3 tests/fixtures/dns/generate_fixtures.py
Regenerates every fixture in this directory. The .pcap outputs are committed
to the repo (per WP-DNS09) so tests need neither protoc nor scapy at test
time; this script is what produced them and is the tool to re-run after
intentionally changing a fixture's content.
"""

import os
import socket
import struct

from scapy.all import Ether, IP, IPv6, Raw, TCP, UDP, wrpcap

FIXED_TIME = 1700000000.0  # 2023-11-14T22:13:20Z, arbitrary and fixed.

OUT_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# Address / endpoint policy constants
# ---------------------------------------------------------------------------

CLIENT_MAC = "02:00:5e:30:00:01"
SERVER_MAC = "02:00:5e:30:00:02"

# The client (stub resolver) and the local DNS service. Client-facing leg:
# ephemeral client port -> :53 on the server, swapped on the response.
CLIENT_IP = "192.0.2.10"
SERVER_IP = "192.0.2.53"

CLIENT_IP6 = "2001:db8::10"
SERVER_IP6 = "2001:db8::53"

CLIENT_PORT = 40000        # fixed ephemeral source port (byte-stable)
DNS_PORT = 53

# Answer record data, all documentation address space.
A_ADDR = "192.0.2.80"
A_ADDR_ALT = "192.0.2.81"
AAAA_ADDR = "2001:db8::80"
NS1_IP = "192.0.2.53"

DOMAIN = "example.com"

# ---------------------------------------------------------------------------
# Byte-level primitives
# ---------------------------------------------------------------------------


def u16(v):
    return struct.pack("!H", v)


def u32(v):
    return struct.pack("!I", v)


def ipv4(s):
    return socket.inet_aton(s)


def ipv6(s):
    return socket.inet_pton(socket.AF_INET6, s)


# DNS TYPE / CLASS / opcode / rcode constants used below.
TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_AAAA = 28
TYPE_OPT = 41
CLASS_IN = 1

# Header flag words (QR/Opcode/AA/TC/RD/RA/Z/RCODE packed into 16 bits).
FLAGS_QUERY_RD = 0x0100          # QR=0, RD=1 (standard recursive query)
FLAGS_RESP_NOERROR = 0x8180      # QR=1, RD=1, RA=1, rcode=0
FLAGS_RESP_NXDOMAIN = 0x8183     # QR=1, RD=1, RA=1, rcode=3 (NXDOMAIN)


def dns_header(dns_id, flags, qd, an, ns, ar):
    return u16(dns_id) + u16(flags) + u16(qd) + u16(an) + u16(ns) + u16(ar)


def dns_name(name):
    """Encode a domain name as uncompressed RFC 1035 labels + root."""
    out = b""
    if name and name != ".":
        for label in name.split("."):
            raw = label.encode("ascii")
            assert 1 <= len(raw) <= 63
            out += bytes([len(raw)]) + raw
    out += b"\x00"
    return out


def name_ptr(offset):
    """A compression pointer (11 + 14-bit offset) to `offset` in the message."""
    assert 0 <= offset < 0x4000
    return bytes([0xC0 | (offset >> 8), offset & 0xFF])


def dns_question(qname, qtype, qclass=CLASS_IN):
    return dns_name(qname) + u16(qtype) + u16(qclass)


def dns_rr(name_bytes, rtype, ttl, rdata, rclass=CLASS_IN):
    return (name_bytes + u16(rtype) + u16(rclass) + u32(ttl) +
            u16(len(rdata)) + rdata)


def edns_ecs_option(family, source_prefix, scope_prefix, addr_bytes):
    """EDNS Client Subnet option (option-code 8, RFC 7871)."""
    optdata = u16(family) + bytes([source_prefix, scope_prefix]) + addr_bytes
    return u16(8) + u16(len(optdata)) + optdata


def edns_opt_rr(udp_size, do_bit, options_bytes):
    """OPT pseudo-RR (RFC 6891): owner=root, type=OPT, class=UDP payload
    size, TTL packs extended-rcode(8)/version(8)/DO(1)/Z(15)."""
    ttl = (0 << 24) | (0 << 16) | ((0x8000 if do_bit else 0))
    return dns_name(".") + u16(TYPE_OPT) + u16(udp_size) + u32(ttl) + \
        u16(len(options_bytes)) + options_bytes


# ---------------------------------------------------------------------------
# Frame wrappers (pin every otherwise-random/host-derived field)
# ---------------------------------------------------------------------------


def udp_frame(eth_src, eth_dst, ip_src, ip_dst, sport, dport, payload):
    pkt = Ether(src=eth_src, dst=eth_dst) / \
        IP(src=ip_src, dst=ip_dst, id=0, ttl=64) / \
        UDP(sport=sport, dport=dport) / Raw(load=payload)
    pkt.time = FIXED_TIME
    return pkt


def udp6_frame(eth_src, eth_dst, ip6_src, ip6_dst, sport, dport, payload):
    pkt = Ether(src=eth_src, dst=eth_dst) / \
        IPv6(src=ip6_src, dst=ip6_dst, hlim=64) / \
        UDP(sport=sport, dport=dport) / Raw(load=payload)
    pkt.time = FIXED_TIME
    return pkt


def tcp_frame(eth_src, eth_dst, ip_src, ip_dst, sport, dport, dns_message):
    """DNS-over-TCP frame: the payload is the 2-byte length prefix (RFC 1035
    section 4.2.2) followed by the DNS message. Seeds must strip the prefix
    before feeding cf_dns_parse (the quick-check does exactly this)."""
    payload = u16(len(dns_message)) + dns_message
    pkt = Ether(src=eth_src, dst=eth_dst) / \
        IP(src=ip_src, dst=ip_dst, id=0, ttl=64) / \
        TCP(sport=sport, dport=dport, flags="PA", seq=1, ack=1, window=8192) / \
        Raw(load=payload)
    pkt.time = FIXED_TIME
    return pkt


def client_query_frame(dns_message):
    return udp_frame(CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP,
                     CLIENT_PORT, DNS_PORT, dns_message)


def server_response_frame(dns_message):
    return udp_frame(SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP,
                     DNS_PORT, CLIENT_PORT, dns_message)


# ---------------------------------------------------------------------------
# Fixture builders. Each returns a single scapy packet.
#
# Compression-pointer offsets: the question always starts at offset 12 (right
# after the fixed 12-byte header), so a pointer to the qname is 0xC00C. The
# "example.com" suffix inside a qname of the form "<label>.example.com" sits
# at 12 + 1 + len(<label>) (one length byte + the first label), which each
# response below computes explicitly.
# ---------------------------------------------------------------------------


def build_q_a_query():
    body = dns_header(0x1001, FLAGS_QUERY_RD, 1, 0, 0, 0)
    body += dns_question("www.example.com", TYPE_A)
    return client_query_frame(body)


def build_q_a_response():
    q = dns_question("www.example.com", TYPE_A)
    body = dns_header(0x1001, FLAGS_RESP_NOERROR, 1, 1, 0, 0)
    body += q
    # Answer owner name is a compression pointer back to the question name.
    body += dns_rr(name_ptr(12), TYPE_A, 300, ipv4(A_ADDR))
    return server_response_frame(body)


def build_q_aaaa_query():
    body = dns_header(0x2002, FLAGS_QUERY_RD, 1, 0, 0, 0)
    body += dns_question("www.example.com", TYPE_AAAA)
    return client_query_frame(body)


def build_q_aaaa_response():
    body = dns_header(0x2002, FLAGS_RESP_NOERROR, 1, 1, 0, 0)
    body += dns_question("www.example.com", TYPE_AAAA)
    body += dns_rr(name_ptr(12), TYPE_AAAA, 300, ipv6(AAAA_ADDR))
    return server_response_frame(body)


def build_q_multi_question():
    # A single query message carrying two questions (qdcount=2): unusual but
    # legal, and a good parser edge case (rare in the wild, must not trip the
    # RR walk). Both questions are decoded; correlation keys on the first.
    body = dns_header(0x3003, FLAGS_QUERY_RD, 2, 0, 0, 0)
    body += dns_question("www.example.com", TYPE_A)
    body += dns_question("mail.example.com", TYPE_AAAA)
    return client_query_frame(body)


def build_q_nxdomain_query():
    body = dns_header(0x4004, FLAGS_QUERY_RD, 1, 0, 0, 0)
    body += dns_question("nonexistent.example.com", TYPE_A)
    return client_query_frame(body)


def build_r_nxdomain_response():
    qname = "nonexistent.example.com"
    q = dns_question(qname, TYPE_A)
    # Offset of the "example.com" suffix within the question name: header(12)
    # + length byte(1) + len("nonexistent").
    example_off = 12 + 1 + len("nonexistent")
    body = dns_header(0x4004, FLAGS_RESP_NXDOMAIN, 1, 0, 1, 0)
    body += q
    # Authority SOA for example.com. Owner name is a compression pointer to
    # the "example.com" suffix of the question. MNAME/RNAME are uncompressed.
    soa_rdata = (dns_name("ns1.example.com") +
                 dns_name("hostmaster.example.com") +
                 u32(2024010101) +   # serial
                 u32(7200) +          # refresh
                 u32(3600) +          # retry
                 u32(1209600) +       # expire
                 u32(3600))           # minimum / negative-cache TTL
    body += dns_rr(name_ptr(example_off), TYPE_SOA, 3600, soa_rdata)
    return server_response_frame(body)


def build_q_edns_ecs_query():
    # A query with an EDNS(0) OPT record carrying an ECS option (code 8) for
    # 192.0.2.0/24. arcount=1 (the OPT record is in the additional section).
    body = dns_header(0x5005, FLAGS_QUERY_RD, 1, 0, 0, 1)
    body += dns_question("www.example.com", TYPE_A)
    ecs = edns_ecs_option(family=1, source_prefix=24, scope_prefix=0,
                          addr_bytes=bytes([192, 0, 2]))
    body += edns_opt_rr(udp_size=4096, do_bit=True, options_bytes=ecs)
    return client_query_frame(body)


def build_r_edns_ecs_response():
    # NOERROR response echoing the ECS option with a populated scope prefix,
    # plus the A answer (compressed owner name).
    body = dns_header(0x5005, FLAGS_RESP_NOERROR, 1, 1, 0, 1)
    body += dns_question("www.example.com", TYPE_A)
    body += dns_rr(name_ptr(12), TYPE_A, 300, ipv4(A_ADDR))
    ecs = edns_ecs_option(family=1, source_prefix=24, scope_prefix=24,
                          addr_bytes=bytes([192, 0, 2]))
    body += edns_opt_rr(udp_size=4096, do_bit=True, options_bytes=ecs)
    return server_response_frame(body)


def build_q_cname_query():
    body = dns_header(0x6006, FLAGS_QUERY_RD, 1, 0, 0, 0)
    body += dns_question("www.example.com", TYPE_A)
    return client_query_frame(body)


def build_r_cname_response():
    # Compression-heavy response: a CNAME chain where every owner and the
    # CNAME target reuse the "example.com" suffix via pointers.
    #   www.example.com.  CNAME web.example.com.
    #   web.example.com.  A     192.0.2.80
    qname = "www.example.com"
    q = dns_question(qname, TYPE_A)
    # "example.com" suffix offset inside the question ("www" first label).
    example_off = 12 + 1 + len("www")
    body = dns_header(0x6006, FLAGS_RESP_NOERROR, 1, 2, 0, 0)
    body += q
    # Answer 1: owner = pointer to question name; CNAME rdata target is
    # "web" + pointer to the example.com suffix.
    cname_target = bytes([3]) + b"web" + name_ptr(example_off)
    body += dns_rr(name_ptr(12), TYPE_CNAME, 300, cname_target)
    # Answer 2: owner = "web" + pointer to example.com suffix (the CNAME
    # target, re-expressed with compression), A record.
    web_name = bytes([3]) + b"web" + name_ptr(example_off)
    body += dns_rr(web_name, TYPE_A, 300, ipv4(A_ADDR_ALT))
    return server_response_frame(body)


def build_tcp_a_query():
    body = dns_header(0x7007, FLAGS_QUERY_RD, 1, 0, 0, 0)
    body += dns_question("www.example.com", TYPE_A)
    return tcp_frame(CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP,
                     CLIENT_PORT, DNS_PORT, body)


def build_tcp_a_response():
    body = dns_header(0x7007, FLAGS_RESP_NOERROR, 1, 1, 0, 0)
    body += dns_question("www.example.com", TYPE_A)
    body += dns_rr(name_ptr(12), TYPE_A, 300, ipv4(A_ADDR))
    return tcp_frame(SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP,
                     DNS_PORT, CLIENT_PORT, body)


def build_malformed_truncated():
    # Header claims one question (qdcount=1) but the message is cut off in
    # the middle of the qname -- the length byte for a label promises more
    # bytes than remain. Parser must bounds-check and never read past the end.
    body = dns_header(0x8008, FLAGS_QUERY_RD, 1, 0, 0, 0)
    body += bytes([3]) + b"www" + bytes([7]) + b"exa"  # "example" truncated
    return client_query_frame(body)


def build_malformed_compression_loop():
    # A qname whose first label is a compression pointer to itself (offset 12
    # points at the pointer we just wrote at offset 12): a self-referential
    # loop the decompressor must detect and abort on rather than spin forever.
    body = dns_header(0x9009, FLAGS_QUERY_RD, 1, 0, 0, 0)
    body += name_ptr(12)          # pointer at offset 12 -> offset 12 (itself)
    body += u16(TYPE_A) + u16(CLASS_IN)
    return client_query_frame(body)


BUILDERS = {
    "q_a_query": build_q_a_query,
    "q_a_response": build_q_a_response,
    "q_aaaa_query": build_q_aaaa_query,
    "q_aaaa_response": build_q_aaaa_response,
    "q_multi_question": build_q_multi_question,
    "q_nxdomain_query": build_q_nxdomain_query,
    "r_nxdomain_response": build_r_nxdomain_response,
    "q_edns_ecs_query": build_q_edns_ecs_query,
    "r_edns_ecs_response": build_r_edns_ecs_response,
    "q_cname_query": build_q_cname_query,
    "r_cname_response": build_r_cname_response,
    "tcp_a_query": build_tcp_a_query,
    "tcp_a_response": build_tcp_a_response,
    "malformed_truncated": build_malformed_truncated,
    "malformed_compression_loop": build_malformed_compression_loop,
}


def main():
    for name, builder in BUILDERS.items():
        pkt = builder()
        pcap_path = os.path.join(OUT_DIR, f"{name}.pcap")
        wrpcap(pcap_path, [pkt])
        print(f"wrote {pcap_path}")


if __name__ == "__main__":
    main()
