/* CUnit acceptance tests for the WP-05 packet decap library
 * (libs/cloudflow-packet/cf_decap.c, cf_ipfmt.c). Standalone binary
 * (build/cf_decap_test), following the "one binary per WP" pattern
 * documented in tests/unit/Makefile (see cf_queue_test.c for the sibling
 * example this file's structure is lifted from).
 *
 * All test frames are hand-built byte arrays (never read from a
 * capture/fixture file) via the small put_*() helpers below, which write
 * big-endian wire fields with memcpy -- matching the discipline the library
 * itself is held to, so a bug in a helper can't silently create a frame
 * that isn't what the test author intended.
 */

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include <string.h>

#include "cf_decap.h"
#include "cf_ipfmt.h"

/* ---- frame-building helpers ---------------------------------------- */

static size_t put_bytes(uint8_t *buf, size_t off, const void *src, size_t n)
{
    if (n != 0)                 /* memcpy(dst, NULL, 0) is UB; a zero-length */
        memcpy(buf + off, src, n); /* copy (e.g. an empty TCP payload) is a no-op */
    return off + n;
}

static size_t put_u8(uint8_t *buf, size_t off, uint8_t v)
{
    buf[off] = v;
    return off + 1;
}

static size_t put_u16(uint8_t *buf, size_t off, uint16_t v)
{
    uint8_t b[2];
    b[0] = (uint8_t)(v >> 8);
    b[1] = (uint8_t)v;
    return put_bytes(buf, off, b, 2);
}

static size_t put_u32(uint8_t *buf, size_t off, uint32_t v)
{
    uint8_t b[4];
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)v;
    return put_bytes(buf, off, b, 4);
}

static const uint8_t DST_MAC[6] = {0x02, 0x00, 0x5e, 0x10, 0x00, 0x01};
static const uint8_t SRC_MAC[6] = {0x02, 0x00, 0x5e, 0x10, 0x00, 0x02};

static size_t put_eth(uint8_t *buf, size_t off, uint16_t ethertype)
{
    off = put_bytes(buf, off, DST_MAC, 6);
    off = put_bytes(buf, off, SRC_MAC, 6);
    off = put_u16(buf, off, ethertype);
    return off;
}

static size_t put_vlan_tag(uint8_t *buf, size_t off, uint16_t vlan_id,
                            uint16_t next_ethertype)
{
    off = put_u16(buf, off, vlan_id & 0x0FFFu); /* PCP/DEI bits left 0 */
    off = put_u16(buf, off, next_ethertype);
    return off;
}

static size_t put_ipv4(uint8_t *buf, size_t off, uint8_t protocol,
                        uint16_t flags_frag, uint8_t tos, uint8_t ttl,
                        const uint8_t src[4], const uint8_t dst[4],
                        uint16_t total_len)
{
    off = put_u8(buf, off, 0x45); /* version 4, IHL 5 (20 bytes, no options) */
    off = put_u8(buf, off, tos);
    off = put_u16(buf, off, total_len);
    off = put_u16(buf, off, 0); /* identification */
    off = put_u16(buf, off, flags_frag);
    off = put_u8(buf, off, ttl);
    off = put_u8(buf, off, protocol);
    off = put_u16(buf, off, 0); /* header checksum, ignored by decap */
    off = put_bytes(buf, off, src, 4);
    off = put_bytes(buf, off, dst, 4);
    return off;
}

static size_t put_ipv6(uint8_t *buf, size_t off, uint8_t next_header,
                        uint8_t hop_limit, const uint8_t src[16],
                        const uint8_t dst[16], uint16_t payload_len)
{
    off = put_u32(buf, off, 0x60000000u); /* version 6, traffic class/flow 0 */
    off = put_u16(buf, off, payload_len);
    off = put_u8(buf, off, next_header);
    off = put_u8(buf, off, hop_limit);
    off = put_bytes(buf, off, src, 16);
    off = put_bytes(buf, off, dst, 16);
    return off;
}

static size_t put_udp(uint8_t *buf, size_t off, uint16_t sport, uint16_t dport,
                       uint16_t checksum, const uint8_t *payload,
                       size_t payload_len)
{
    off = put_u16(buf, off, sport);
    off = put_u16(buf, off, dport);
    off = put_u16(buf, off, (uint16_t)(8 + payload_len));
    off = put_u16(buf, off, checksum);
    off = put_bytes(buf, off, payload, payload_len);
    return off;
}

/* A minimal 20-byte TCP header (no options), followed by `payload`. The
 * data-offset high nibble encodes the header length in 32-bit words; 5 words
 * = the 20-byte minimum. `flags` is the raw FIN/SYN/RST/PSH/ACK/... byte. */
static size_t put_tcp(uint8_t *buf, size_t off, uint16_t sport, uint16_t dport,
                       uint32_t seq, uint8_t flags, const uint8_t *payload,
                       size_t payload_len)
{
    off = put_u16(buf, off, sport);
    off = put_u16(buf, off, dport);
    off = put_u32(buf, off, seq);
    off = put_u32(buf, off, 0);       /* ack number, ignored by decap */
    off = put_u8(buf, off, 0x50);     /* data offset 5 words (20 bytes), reserved 0 */
    off = put_u8(buf, off, flags);
    off = put_u16(buf, off, 0);       /* window, ignored by decap */
    off = put_u16(buf, off, 0);       /* checksum, ignored by decap */
    off = put_u16(buf, off, 0);       /* urgent pointer, ignored by decap */
    off = put_bytes(buf, off, payload, payload_len);
    return off;
}

/* IPv6 hop-by-hop / dest-options / routing extension header with no real
 * option data: hdr_ext_len 0 means "8 bytes total"; the 6 bytes after
 * next_header/hdr_ext_len are Pad1 (value 0) options. */
static size_t put_ext_header(uint8_t *buf, size_t off, uint8_t next_header)
{
    off = put_u8(buf, off, next_header);
    off = put_u8(buf, off, 0);
    for (int i = 0; i < 6; i++)
        off = put_u8(buf, off, 0);
    return off;
}

static const uint8_t V4_SRC[4] = {192, 0, 2, 1};
static const uint8_t V4_DST[4] = {192, 0, 2, 2};
static const uint8_t V6_SRC[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                    0,    0,    0,    0,    0, 0, 0, 1};
static const uint8_t V6_DST[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                    0,    0,    0,    0,    0, 0, 0, 2};

static const uint8_t PAYLOAD[] = {'H', 'E', 'L', 'L', 'O'};

/* ---- basic shapes ---------------------------------------------------- */

static void test_plain_ipv4_udp(void)
{
    uint8_t frame[128];
    size_t off = 0;
    cf_decap_udp_t out;

    off = put_eth(frame, off, 0x0800);
    off = put_ipv4(frame, off, 17, 0, 0x88 /* DSCP 34, ECN 0 */, 64,
                    V4_SRC, V4_DST, (uint16_t)(20 + 8 + sizeof(PAYLOAD)));
    off = put_udp(frame, off, 68, 67, 0x1234, PAYLOAD, sizeof(PAYLOAD));

    CU_ASSERT_EQUAL(cf_decap_udp(frame, off, &out), CF_DECAP_OK);
    CU_ASSERT_EQUAL(out.ip_version, 4);
    CU_ASSERT_EQUAL(out.vlan_count, 0);
    CU_ASSERT_EQUAL(out.ethertype, 0x0800);
    CU_ASSERT_EQUAL(memcmp(out.src_mac, SRC_MAC, 6), 0);
    CU_ASSERT_EQUAL(memcmp(out.dst_mac, DST_MAC, 6), 0);
    CU_ASSERT_EQUAL(memcmp(out.src_ip, V4_SRC, 4), 0);
    CU_ASSERT_EQUAL(memcmp(out.dst_ip, V4_DST, 4), 0);
    CU_ASSERT_EQUAL(out.next_header, 17);
    CU_ASSERT_EQUAL(out.ttl_or_hop_limit, 64);
    CU_ASSERT_EQUAL(out.dscp, 0x88 >> 2);
    CU_ASSERT_EQUAL(out.ecn, 0x88 & 0x3);
    CU_ASSERT_EQUAL(out.fragmented, 0);
    CU_ASSERT_EQUAL(out.fragment_offset, 0);
    CU_ASSERT_EQUAL(out.src_port, 68);
    CU_ASSERT_EQUAL(out.dst_port, 67);
    CU_ASSERT_EQUAL(out.udp_length, 8 + sizeof(PAYLOAD));
    CU_ASSERT_EQUAL(out.udp_checksum_present, 1);
    CU_ASSERT_EQUAL(out.payload_len, sizeof(PAYLOAD));
    CU_ASSERT_EQUAL(memcmp(out.payload, PAYLOAD, sizeof(PAYLOAD)), 0);
}

static void test_single_vlan(void)
{
    uint8_t frame[128];
    size_t off = 0;
    cf_decap_udp_t out;

    off = put_eth(frame, off, 0x8100);
    off = put_vlan_tag(frame, off, 42, 0x0800);
    off = put_ipv4(frame, off, 17, 0, 0, 64, V4_SRC, V4_DST,
                    (uint16_t)(20 + 8 + sizeof(PAYLOAD)));
    off = put_udp(frame, off, 68, 67, 0x1234, PAYLOAD, sizeof(PAYLOAD));

    CU_ASSERT_EQUAL(cf_decap_udp(frame, off, &out), CF_DECAP_OK);
    CU_ASSERT_EQUAL(out.vlan_count, 1);
    CU_ASSERT_EQUAL(out.vlan_ids[0], 42);
    CU_ASSERT_EQUAL(out.ethertype, 0x0800);
    CU_ASSERT_EQUAL(out.ip_version, 4);
}

static void test_qinq_double_tag(void)
{
    uint8_t frame[128];
    size_t off = 0;
    cf_decap_udp_t out;

    off = put_eth(frame, off, 0x88A8);
    off = put_vlan_tag(frame, off, 100, 0x8100);
    off = put_vlan_tag(frame, off, 200, 0x0800);
    off = put_ipv4(frame, off, 17, 0, 0, 64, V4_SRC, V4_DST,
                    (uint16_t)(20 + 8 + sizeof(PAYLOAD)));
    off = put_udp(frame, off, 68, 67, 0x1234, PAYLOAD, sizeof(PAYLOAD));

    CU_ASSERT_EQUAL(cf_decap_udp(frame, off, &out), CF_DECAP_OK);
    CU_ASSERT_EQUAL(out.vlan_count, 2);
    CU_ASSERT_EQUAL(out.vlan_ids[0], 100);
    CU_ASSERT_EQUAL(out.vlan_ids[1], 200);
    CU_ASSERT_EQUAL(out.ethertype, 0x0800);
}

static void test_plain_ipv6_udp(void)
{
    uint8_t frame[128];
    size_t off = 0;
    cf_decap_udp_t out;

    off = put_eth(frame, off, 0x86DD);
    off = put_ipv6(frame, off, 17, 64, V6_SRC, V6_DST,
                    (uint16_t)(8 + sizeof(PAYLOAD)));
    off = put_udp(frame, off, 546, 547, 0xABCD, PAYLOAD, sizeof(PAYLOAD));

    CU_ASSERT_EQUAL(cf_decap_udp(frame, off, &out), CF_DECAP_OK);
    CU_ASSERT_EQUAL(out.ip_version, 6);
    CU_ASSERT_EQUAL(memcmp(out.src_ip, V6_SRC, 16), 0);
    CU_ASSERT_EQUAL(memcmp(out.dst_ip, V6_DST, 16), 0);
    CU_ASSERT_EQUAL(out.next_header, 17);
    CU_ASSERT_EQUAL(out.ttl_or_hop_limit, 64);
    CU_ASSERT_EQUAL(out.src_port, 546);
    CU_ASSERT_EQUAL(out.dst_port, 547);
    CU_ASSERT_EQUAL(out.payload_len, sizeof(PAYLOAD));
    CU_ASSERT_EQUAL(memcmp(out.payload, PAYLOAD, sizeof(PAYLOAD)), 0);
}

static void test_ipv6_hop_by_hop_ext_header(void)
{
    uint8_t frame[128];
    size_t off = 0;
    cf_decap_udp_t out;

    off = put_eth(frame, off, 0x86DD);
    off = put_ipv6(frame, off, 0 /* hop-by-hop */, 64, V6_SRC, V6_DST,
                    (uint16_t)(8 + 8 + sizeof(PAYLOAD)));
    off = put_ext_header(frame, off, 17 /* next: UDP */);
    off = put_udp(frame, off, 546, 547, 0xABCD, PAYLOAD, sizeof(PAYLOAD));

    CU_ASSERT_EQUAL(cf_decap_udp(frame, off, &out), CF_DECAP_OK);
    CU_ASSERT_EQUAL(out.ip_version, 6);
    CU_ASSERT_EQUAL(out.next_header, 17);
    CU_ASSERT_EQUAL(out.payload_len, sizeof(PAYLOAD));
    CU_ASSERT_EQUAL(memcmp(out.payload, PAYLOAD, sizeof(PAYLOAD)), 0);
}

/* ---- fragments and non-UDP -------------------------------------------- */

static void test_ipv4_fragment_offset_nonzero_not_udp(void)
{
    uint8_t frame[128];
    size_t off = 0;
    cf_decap_udp_t out;
    uint16_t flags_frag = 5; /* MF=0, fragment offset = 5 (nonzero) */

    off = put_eth(frame, off, 0x0800);
    off = put_ipv4(frame, off, 17, flags_frag, 0, 64, V4_SRC, V4_DST, 20 + 40);
    /* No UDP header present in a non-first fragment; pad with filler bytes. */
    memset(frame + off, 0, 40);
    off += 40;

    CU_ASSERT_EQUAL(cf_decap_udp(frame, off, &out), CF_DECAP_NOT_UDP);
    CU_ASSERT_EQUAL(out.fragmented, 1);
    CU_ASSERT_EQUAL(out.fragment_offset, 5);
}

static void test_ipv4_first_fragment_mf_ok_and_fragmented(void)
{
    uint8_t frame[128];
    size_t off = 0;
    cf_decap_udp_t out;
    uint16_t flags_frag = 0x2000; /* MF=1, fragment offset = 0 */

    off = put_eth(frame, off, 0x0800);
    off = put_ipv4(frame, off, 17, flags_frag, 0, 64, V4_SRC, V4_DST,
                    (uint16_t)(20 + 8 + sizeof(PAYLOAD)));
    off = put_udp(frame, off, 68, 67, 0x1234, PAYLOAD, sizeof(PAYLOAD));

    CU_ASSERT_EQUAL(cf_decap_udp(frame, off, &out), CF_DECAP_OK);
    CU_ASSERT_EQUAL(out.fragmented, 1);
    CU_ASSERT_EQUAL(out.fragment_offset, 0);
    CU_ASSERT_EQUAL(out.payload_len, sizeof(PAYLOAD));
}

static void test_non_udp_protocol_not_udp(void)
{
    uint8_t frame[128];
    size_t off = 0;
    cf_decap_udp_t out;

    off = put_eth(frame, off, 0x0800);
    off = put_ipv4(frame, off, 6 /* TCP */, 0, 0, 64, V4_SRC, V4_DST, 20 + 20);
    memset(frame + off, 0, 20);
    off += 20;

    CU_ASSERT_EQUAL(cf_decap_udp(frame, off, &out), CF_DECAP_NOT_UDP);
    CU_ASSERT_EQUAL(out.next_header, 6);
}

/* ---- unsupported shapes ------------------------------------------------ */

static void test_more_than_two_vlan_tags_unsupported(void)
{
    uint8_t frame[128];
    size_t off = 0;
    cf_decap_udp_t out;

    off = put_eth(frame, off, 0x8100);
    off = put_vlan_tag(frame, off, 10, 0x8100);
    /* Second tag's "next ethertype" is itself a VLAN TPID -- a third tag,
     * which the library must reject without needing its body present. */
    off = put_vlan_tag(frame, off, 20, 0x8100);

    CU_ASSERT_EQUAL(cf_decap_udp(frame, off, &out), CF_DECAP_UNSUPPORTED);
}

static void test_unknown_ethertype_unsupported(void)
{
    uint8_t frame[64];
    size_t off = 0;
    cf_decap_udp_t out;

    off = put_eth(frame, off, 0x0806); /* ARP */
    memset(frame + off, 0, 28);
    off += 28;

    CU_ASSERT_EQUAL(cf_decap_udp(frame, off, &out), CF_DECAP_UNSUPPORTED);
}

/* ---- truncation sweep --------------------------------------------------
 *
 * For a valid v4 and a valid v6 frame, cf_decap_udp must never crash for
 * any prefix length 0..full-1, and whenever it returns CF_DECAP_OK the
 * reported payload must lie entirely within the bytes actually passed in
 * (never past `frame + len`), even though `out.payload` points into the
 * full underlying buffer.
 */

static void assert_truncation_safe(const uint8_t *frame, size_t full_len)
{
    for (size_t len = 0; len < full_len; len++) {
        cf_decap_udp_t out;
        cf_decap_result_t rc = cf_decap_udp(frame, len, &out);

        switch (rc) {
        case CF_DECAP_OK:
        case CF_DECAP_NOT_UDP:
        case CF_DECAP_TRUNCATED:
        case CF_DECAP_UNSUPPORTED:
            break;
        default:
            CU_FAIL("cf_decap_udp returned an out-of-range result code");
            return;
        }

        if (rc == CF_DECAP_OK) {
            CU_ASSERT_TRUE(out.payload >= frame);
            CU_ASSERT_TRUE(out.payload + out.payload_len <= frame + len);
        }
    }
}

static void test_truncation_sweep_ipv4(void)
{
    uint8_t frame[128];
    size_t off = 0;

    off = put_eth(frame, off, 0x0800);
    off = put_ipv4(frame, off, 17, 0, 0, 64, V4_SRC, V4_DST,
                    (uint16_t)(20 + 8 + sizeof(PAYLOAD)));
    off = put_udp(frame, off, 68, 67, 0x1234, PAYLOAD, sizeof(PAYLOAD));

    assert_truncation_safe(frame, off);
}

static void test_truncation_sweep_ipv6(void)
{
    uint8_t frame[128];
    size_t off = 0;

    off = put_eth(frame, off, 0x86DD);
    off = put_ipv6(frame, off, 17, 64, V6_SRC, V6_DST,
                    (uint16_t)(8 + sizeof(PAYLOAD)));
    off = put_udp(frame, off, 546, 547, 0xABCD, PAYLOAD, sizeof(PAYLOAD));

    assert_truncation_safe(frame, off);
}

/* ---- cf_decap_tcp (single-segment, WP-DNS02) --------------------------
 *
 * A DNS-over-TCP payload: the 2-byte big-endian length prefix plus a short
 * DNS-shaped message. cf_decap is protocol-agnostic -- it exposes the whole
 * thing as the raw TCP payload and does NOT interpret the length prefix; the
 * DNS layer (a later WP) does that.
 */
static const uint8_t DNS_TCP_PAYLOAD[] = {
    0x00, 0x0c,             /* length prefix: 12 bytes of DNS follow */
    0x12, 0x34,             /* dns transaction id */
    0x01, 0x00,             /* flags: standard query, RD */
    0x00, 0x01,             /* qdcount = 1 */
    0x00, 0x00,             /* ancount = 0 */
    0x00, 0x00,             /* nscount = 0 */
    0x00, 0x00              /* arcount = 0 */
};

static void test_ipv4_tcp_dns_port53(void)
{
    uint8_t frame[128];
    size_t off = 0;
    cf_decap_tcp_t out;

    off = put_eth(frame, off, 0x0800);
    off = put_ipv4(frame, off, 6 /* TCP */, 0, 0x88 /* DSCP 34 */, 64,
                    V4_SRC, V4_DST,
                    (uint16_t)(20 + 20 + sizeof(DNS_TCP_PAYLOAD)));
    off = put_tcp(frame, off, 5300, 53, 0xDEADBEEFu, 0x18 /* PSH+ACK */,
                   DNS_TCP_PAYLOAD, sizeof(DNS_TCP_PAYLOAD));

    CU_ASSERT_EQUAL(cf_decap_tcp(frame, off, &out), CF_DECAP_OK);
    CU_ASSERT_EQUAL(out.ip_version, 4);
    CU_ASSERT_EQUAL(out.next_header, 6);
    CU_ASSERT_EQUAL(out.src_port, 5300);
    CU_ASSERT_EQUAL(out.dst_port, 53);
    CU_ASSERT_EQUAL(out.seq, 0xDEADBEEFu);
    CU_ASSERT_EQUAL(out.tcp_flags, 0x18);
    CU_ASSERT_EQUAL(out.payload_len, sizeof(DNS_TCP_PAYLOAD));
    CU_ASSERT_EQUAL(memcmp(out.payload, DNS_TCP_PAYLOAD,
                            sizeof(DNS_TCP_PAYLOAD)), 0);
}

static void test_ipv6_tcp(void)
{
    uint8_t frame[128];
    size_t off = 0;
    cf_decap_tcp_t out;

    off = put_eth(frame, off, 0x86DD);
    off = put_ipv6(frame, off, 6 /* TCP */, 64, V6_SRC, V6_DST,
                    (uint16_t)(20 + sizeof(DNS_TCP_PAYLOAD)));
    off = put_tcp(frame, off, 5300, 53, 1, 0x10 /* ACK */,
                   DNS_TCP_PAYLOAD, sizeof(DNS_TCP_PAYLOAD));

    CU_ASSERT_EQUAL(cf_decap_tcp(frame, off, &out), CF_DECAP_OK);
    CU_ASSERT_EQUAL(out.ip_version, 6);
    CU_ASSERT_EQUAL(memcmp(out.src_ip, V6_SRC, 16), 0);
    CU_ASSERT_EQUAL(memcmp(out.dst_ip, V6_DST, 16), 0);
    CU_ASSERT_EQUAL(out.next_header, 6);
    CU_ASSERT_EQUAL(out.dst_port, 53);
    CU_ASSERT_EQUAL(out.payload_len, sizeof(DNS_TCP_PAYLOAD));
    CU_ASSERT_EQUAL(memcmp(out.payload, DNS_TCP_PAYLOAD,
                            sizeof(DNS_TCP_PAYLOAD)), 0);
}

static void test_ipv4_tcp_single_vlan(void)
{
    uint8_t frame[128];
    size_t off = 0;
    cf_decap_tcp_t out;

    off = put_eth(frame, off, 0x8100);
    off = put_vlan_tag(frame, off, 77, 0x0800);
    off = put_ipv4(frame, off, 6 /* TCP */, 0, 0, 64, V4_SRC, V4_DST,
                    (uint16_t)(20 + 20 + sizeof(DNS_TCP_PAYLOAD)));
    off = put_tcp(frame, off, 5300, 53, 1, 0x10, DNS_TCP_PAYLOAD,
                   sizeof(DNS_TCP_PAYLOAD));

    CU_ASSERT_EQUAL(cf_decap_tcp(frame, off, &out), CF_DECAP_OK);
    CU_ASSERT_EQUAL(out.vlan_count, 1);
    CU_ASSERT_EQUAL(out.vlan_ids[0], 77);
    CU_ASSERT_EQUAL(out.ip_version, 4);
    CU_ASSERT_EQUAL(out.dst_port, 53);
    CU_ASSERT_EQUAL(out.payload_len, sizeof(DNS_TCP_PAYLOAD));
}

static void test_ipv4_tcp_truncated_header(void)
{
    uint8_t frame[128];
    size_t off = 0;
    cf_decap_tcp_t out;

    off = put_eth(frame, off, 0x0800);
    off = put_ipv4(frame, off, 6 /* TCP */, 0, 0, 64, V4_SRC, V4_DST,
                    20 + 20);
    /* Only 10 bytes of the 20-byte TCP header are actually present. */
    memset(frame + off, 0, 10);
    off += 10;

    CU_ASSERT_EQUAL(cf_decap_tcp(frame, off, &out), CF_DECAP_TRUNCATED);
}

static void test_ipv4_tcp_data_offset_past_segment(void)
{
    uint8_t frame[128];
    size_t off = 0;
    cf_decap_tcp_t out;
    size_t tcp_off;

    off = put_eth(frame, off, 0x0800);
    off = put_ipv4(frame, off, 6 /* TCP */, 0, 0, 64, V4_SRC, V4_DST,
                    20 + 20);
    tcp_off = off;
    off = put_tcp(frame, off, 5300, 53, 1, 0x10, NULL, 0);
    /* Rewrite the data-offset nibble to claim a 60-byte (15-word) header,
     * far past the 20 bytes actually captured. */
    frame[tcp_off + 12] = 0xF0;

    CU_ASSERT_EQUAL(cf_decap_tcp(frame, off, &out), CF_DECAP_TRUNCATED);
}

static void test_udp_frame_to_tcp_not_tcp(void)
{
    uint8_t frame[128];
    size_t off = 0;
    cf_decap_tcp_t out;

    off = put_eth(frame, off, 0x0800);
    off = put_ipv4(frame, off, 17 /* UDP */, 0, 0, 64, V4_SRC, V4_DST,
                    (uint16_t)(20 + 8 + sizeof(PAYLOAD)));
    off = put_udp(frame, off, 68, 67, 0x1234, PAYLOAD, sizeof(PAYLOAD));

    CU_ASSERT_EQUAL(cf_decap_tcp(frame, off, &out), CF_DECAP_NOT_TCP);
    CU_ASSERT_EQUAL(out.next_header, 17);
}

static void test_ipv4_tcp_nonfirst_fragment_not_tcp(void)
{
    uint8_t frame[128];
    size_t off = 0;
    cf_decap_tcp_t out;
    uint16_t flags_frag = 9; /* MF=0, fragment offset = 9 (nonzero) */

    off = put_eth(frame, off, 0x0800);
    off = put_ipv4(frame, off, 6 /* TCP */, flags_frag, 0, 64, V4_SRC, V4_DST,
                    20 + 40);
    /* A non-first fragment carries no TCP header; pad with filler bytes. */
    memset(frame + off, 0, 40);
    off += 40;

    CU_ASSERT_EQUAL(cf_decap_tcp(frame, off, &out), CF_DECAP_NOT_TCP);
    CU_ASSERT_EQUAL(out.fragmented, 1);
    CU_ASSERT_EQUAL(out.fragment_offset, 9);
}

/* Regression: an existing-style UDP frame must still decode correctly through
 * cf_decap_udp after the shared-walk refactor. */
static void test_udp_still_decodes_after_refactor(void)
{
    uint8_t frame[128];
    size_t off = 0;
    cf_decap_udp_t out;

    off = put_eth(frame, off, 0x0800);
    off = put_ipv4(frame, off, 17, 0, 0x88, 64, V4_SRC, V4_DST,
                    (uint16_t)(20 + 8 + sizeof(PAYLOAD)));
    off = put_udp(frame, off, 68, 67, 0x1234, PAYLOAD, sizeof(PAYLOAD));

    CU_ASSERT_EQUAL(cf_decap_udp(frame, off, &out), CF_DECAP_OK);
    CU_ASSERT_EQUAL(out.ip_version, 4);
    CU_ASSERT_EQUAL(out.next_header, 17);
    CU_ASSERT_EQUAL(out.src_port, 68);
    CU_ASSERT_EQUAL(out.dst_port, 67);
    CU_ASSERT_EQUAL(out.dscp, 0x88 >> 2);
    CU_ASSERT_EQUAL(out.payload_len, sizeof(PAYLOAD));
    CU_ASSERT_EQUAL(memcmp(out.payload, PAYLOAD, sizeof(PAYLOAD)), 0);
}

/* ---- cf_ipfmt ----------------------------------------------------------- */

static void test_format_mac(void)
{
    char buf[18];
    static const uint8_t mac[6] = {0x02, 0x00, 0x5e, 0x01, 0x02, 0x03};

    cf_format_mac(buf, mac);
    CU_ASSERT_STRING_EQUAL(buf, "02:00:5e:01:02:03");
}

static void test_format_ip_v4(void)
{
    char buf[46];
    uint8_t ip[16] = {0};
    memcpy(ip, V4_SRC, 4);

    cf_format_ip(buf, 4, ip);
    CU_ASSERT_STRING_EQUAL(buf, "192.0.2.1");
}

static void test_format_ip_v6(void)
{
    char buf[46];

    /* 2001:0db8:0000:0000:0000:0000:0000:0001 -> RFC 5952 zero-run
     * compressed form "2001:db8::1", matching inet_ntop(). */
    cf_format_ip(buf, 6, V6_SRC);
    CU_ASSERT_STRING_EQUAL(buf, "2001:db8::1");
}

/* ---- driver -------------------------------------------------------- */

int main(void)
{
    CU_pSuite suite;
    unsigned int failed;

    if (CU_initialize_registry() != CUE_SUCCESS)
        return (int)CU_get_error();

    suite = CU_add_suite("cf_decap", NULL, NULL);
    if (!suite) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    if (!CU_add_test(suite, "plain IPv4/UDP", test_plain_ipv4_udp) ||
        !CU_add_test(suite, "single VLAN tag", test_single_vlan) ||
        !CU_add_test(suite, "QinQ double VLAN tag", test_qinq_double_tag) ||
        !CU_add_test(suite, "plain IPv6/UDP", test_plain_ipv6_udp) ||
        !CU_add_test(suite, "IPv6 with one hop-by-hop ext header",
                      test_ipv6_hop_by_hop_ext_header) ||
        !CU_add_test(suite, "IPv4 fragment offset != 0 -> NOT_UDP",
                      test_ipv4_fragment_offset_nonzero_not_udp) ||
        !CU_add_test(suite, "IPv4 first fragment (MF, offset 0) -> OK + fragmented",
                      test_ipv4_first_fragment_mf_ok_and_fragmented) ||
        !CU_add_test(suite, "non-UDP protocol -> NOT_UDP",
                      test_non_udp_protocol_not_udp) ||
        !CU_add_test(suite, ">2 VLAN tags -> UNSUPPORTED",
                      test_more_than_two_vlan_tags_unsupported) ||
        !CU_add_test(suite, "unknown ethertype -> UNSUPPORTED",
                      test_unknown_ethertype_unsupported) ||
        !CU_add_test(suite, "truncation sweep IPv4", test_truncation_sweep_ipv4) ||
        !CU_add_test(suite, "truncation sweep IPv6", test_truncation_sweep_ipv6) ||
        !CU_add_test(suite, "IPv4 TCP dst-port 53 (DNS-over-TCP payload)",
                      test_ipv4_tcp_dns_port53) ||
        !CU_add_test(suite, "IPv6 TCP", test_ipv6_tcp) ||
        !CU_add_test(suite, "single-VLAN IPv4 TCP", test_ipv4_tcp_single_vlan) ||
        !CU_add_test(suite, "truncated TCP header -> TRUNCATED",
                      test_ipv4_tcp_truncated_header) ||
        !CU_add_test(suite, "TCP data offset past segment -> TRUNCATED",
                      test_ipv4_tcp_data_offset_past_segment) ||
        !CU_add_test(suite, "UDP frame to cf_decap_tcp -> NOT_TCP",
                      test_udp_frame_to_tcp_not_tcp) ||
        !CU_add_test(suite, "IPv4 non-first fragment TCP -> NOT_TCP",
                      test_ipv4_tcp_nonfirst_fragment_not_tcp) ||
        !CU_add_test(suite, "UDP still decodes after refactor",
                      test_udp_still_decodes_after_refactor) ||
        !CU_add_test(suite, "cf_format_mac", test_format_mac) ||
        !CU_add_test(suite, "cf_format_ip v4", test_format_ip_v4) ||
        !CU_add_test(suite, "cf_format_ip v6 zero-run compression",
                      test_format_ip_v6)) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();

    failed = CU_get_number_of_tests_failed();

    CU_cleanup_registry();

    return failed > 0 ? 1 : 0;
}
