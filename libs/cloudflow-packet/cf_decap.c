/* libs/cloudflow-packet/cf_decap.c
 *
 * Ethernet -> (up to 2 VLAN tags) -> IPv4/IPv6 -> UDP decapsulation. See
 * cf_decap.h and docs/design/02-packet-and-parsing.md (WP-05) for the
 * contract.
 *
 * Every multi-byte read is a memcpy into a local variable followed by an
 * explicit ntohs/ntohl-equivalent conversion -- never a pointer cast into
 * `frame`, so this never triggers alignment or strict-aliasing UB no matter
 * how the caller's buffer happens to be aligned. Every offset advance is
 * preceded by an explicit bounds check against `frame_len` (see REMAIN()
 * below), so truncated/adversarial input can only ever produce a defined
 * error return -- it can't read past the end of the frame.
 */

#include "cf_decap.h"

#include <string.h>

#define ETHERTYPE_VLAN   0x8100u /* 802.1Q */
#define ETHERTYPE_QINQ   0x88A8u /* 802.1ad (QinQ outer tag) */
#define ETHERTYPE_IPV4   0x0800u
#define ETHERTYPE_IPV6   0x86DDu

#define IP_PROTO_UDP      17u
#define IPV6_PROTO_HOPOPTS  0u
#define IPV6_PROTO_ROUTING 43u
#define IPV6_PROTO_FRAGMENT 44u
#define IPV6_PROTO_DSTOPTS 60u

#define ETH_HDR_LEN 14u
#define VLAN_TAG_LEN 4u
#define IPV4_MIN_HDR_LEN 20u
#define IPV6_FIXED_HDR_LEN 40u
#define IPV6_FRAG_HDR_LEN 8u
#define UDP_HDR_LEN 8u

/* Max number of IPv6 extension headers (hop-by-hop/dest-options/routing/
 * fragment) walked while looking for the UDP header, per the WP-05 spec. */
#define IPV6_MAX_EXT_HEADERS 8

/* Bytes remaining in the frame starting at `off`, saturating at 0 instead
 * of underflowing if `off` is (incorrectly) past `len` -- keeps every
 * bounds check below a simple "< need" comparison with no risk of size_t
 * wraparound. */
static size_t remain(size_t len, size_t off)
{
    return off > len ? 0 : len - off;
}

static uint16_t read_u16(const uint8_t *p)
{
    uint16_t v;
    memcpy(&v, p, sizeof(v));
    return (uint16_t)((v << 8) | (v >> 8));
}

static uint32_t read_u32(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return ((v & 0x000000FFu) << 24) |
           ((v & 0x0000FF00u) << 8)  |
           ((v & 0x00FF0000u) >> 8)  |
           ((v & 0xFF000000u) >> 24);
}

/* Parses the UDP header at `frame[offset..]` into `out`, including the
 * payload view. Requires the caller to have already established that
 * `offset` is the start of a UDP header for a non-fragmented-or-first
 * fragment (fragmentation bookkeeping is done by the callers). */
static cf_decap_result_t parse_udp(const uint8_t *frame, size_t frame_len,
                                    size_t offset, cf_decap_udp_t *out)
{
    uint16_t udp_len, checksum;

    if (remain(frame_len, offset) < UDP_HDR_LEN)
        return CF_DECAP_TRUNCATED;

    out->src_port = read_u16(frame + offset);
    out->dst_port = read_u16(frame + offset + 2);
    udp_len       = read_u16(frame + offset + 4);
    checksum      = read_u16(frame + offset + 6);

    if (udp_len < UDP_HDR_LEN)
        return CF_DECAP_TRUNCATED; /* header claims a length shorter than itself */

    if (remain(frame_len, offset + UDP_HDR_LEN) < (size_t)(udp_len - UDP_HDR_LEN))
        return CF_DECAP_TRUNCATED; /* frame shorter than the UDP length claims */

    out->udp_length            = udp_len;
    out->udp_checksum_present  = checksum != 0;
    out->payload                = frame + offset + UDP_HDR_LEN;
    out->payload_len            = (size_t)(udp_len - UDP_HDR_LEN);

    return CF_DECAP_OK;
}

static cf_decap_result_t parse_ipv4(const uint8_t *frame, size_t frame_len,
                                     size_t offset, cf_decap_udp_t *out)
{
    uint8_t version_ihl, tos, ttl, protocol;
    uint16_t flags_frag;
    size_t ihl;

    if (remain(frame_len, offset) < IPV4_MIN_HDR_LEN)
        return CF_DECAP_TRUNCATED;

    version_ihl = frame[offset];
    if ((version_ihl >> 4) != 4)
        return CF_DECAP_UNSUPPORTED; /* ethertype said v4 but header disagrees */

    ihl = (size_t)(version_ihl & 0x0Fu) * 4u;
    if (ihl < IPV4_MIN_HDR_LEN || remain(frame_len, offset) < ihl)
        return CF_DECAP_TRUNCATED;

    tos       = frame[offset + 1];
    flags_frag = read_u16(frame + offset + 6);
    ttl       = frame[offset + 8];
    protocol  = frame[offset + 9];

    out->ip_version = 4;
    memcpy(out->src_ip, frame + offset + 12, 4);
    memcpy(out->dst_ip, frame + offset + 16, 4);
    out->next_header       = protocol;
    out->ttl_or_hop_limit  = ttl;
    out->dscp              = (uint8_t)(tos >> 2);
    out->ecn               = (uint8_t)(tos & 0x3u);

    {
        uint16_t frag_offset13 = flags_frag & 0x1FFFu;
        uint8_t  more_fragments = (flags_frag & 0x2000u) != 0;

        out->fragment_offset = frag_offset13;

        if (frag_offset13 != 0) {
            /* non-first fragment: no UDP header present here */
            out->fragmented = 1;
            return CF_DECAP_NOT_UDP;
        }

        out->fragmented = more_fragments;
    }

    if (protocol != IP_PROTO_UDP)
        return CF_DECAP_NOT_UDP;

    return parse_udp(frame, frame_len, offset + ihl, out);
}

static cf_decap_result_t parse_ipv6(const uint8_t *frame, size_t frame_len,
                                     size_t offset, cf_decap_udp_t *out)
{
    uint32_t word0;
    uint8_t version, traffic_class, next_header, hop_limit;
    size_t cur_offset;
    int i;

    if (remain(frame_len, offset) < IPV6_FIXED_HDR_LEN)
        return CF_DECAP_TRUNCATED;

    word0 = read_u32(frame + offset);
    version       = (uint8_t)(word0 >> 28);
    traffic_class = (uint8_t)((word0 >> 20) & 0xFFu);
    if (version != 6)
        return CF_DECAP_UNSUPPORTED;

    next_header = frame[offset + 6];
    hop_limit   = frame[offset + 7];

    out->ip_version = 6;
    memcpy(out->src_ip, frame + offset + 8, 16);
    memcpy(out->dst_ip, frame + offset + 24, 16);
    out->ttl_or_hop_limit = hop_limit;
    out->dscp             = (uint8_t)(traffic_class >> 2);
    out->ecn              = (uint8_t)(traffic_class & 0x3u);
    out->next_header      = next_header;

    cur_offset = offset + IPV6_FIXED_HDR_LEN;

    for (i = 0; i < IPV6_MAX_EXT_HEADERS; i++) {
        if (next_header == IP_PROTO_UDP) {
            out->next_header = next_header;
            return parse_udp(frame, frame_len, cur_offset, out);
        }

        if (next_header == IPV6_PROTO_FRAGMENT) {
            uint16_t off_res_m;
            uint8_t  frag_next_header;
            uint16_t frag_offset13;

            if (remain(frame_len, cur_offset) < IPV6_FRAG_HDR_LEN)
                return CF_DECAP_TRUNCATED;

            frag_next_header = frame[cur_offset];
            off_res_m        = read_u16(frame + cur_offset + 2);
            frag_offset13    = off_res_m >> 3;

            out->next_header      = frag_next_header;
            out->fragment_offset  = frag_offset13;

            if (frag_offset13 != 0) {
                out->fragmented = 1;
                return CF_DECAP_NOT_UDP; /* non-first fragment */
            }

            out->fragmented = 1;
            next_header = frag_next_header;
            cur_offset += IPV6_FRAG_HDR_LEN;
            continue;
        }

        if (next_header == IPV6_PROTO_HOPOPTS ||
            next_header == IPV6_PROTO_ROUTING ||
            next_header == IPV6_PROTO_DSTOPTS) {
            uint8_t ext_next_header, hdr_ext_len;
            size_t  ext_total_len;

            if (remain(frame_len, cur_offset) < 2)
                return CF_DECAP_TRUNCATED;

            ext_next_header = frame[cur_offset];
            hdr_ext_len     = frame[cur_offset + 1];
            ext_total_len   = ((size_t)hdr_ext_len + 1u) * 8u;

            if (remain(frame_len, cur_offset) < ext_total_len)
                return CF_DECAP_TRUNCATED;

            out->next_header = ext_next_header;
            next_header = ext_next_header;
            cur_offset += ext_total_len;
            continue;
        }

        /* Unknown/unsupported next-header (TCP, ICMPv6, ESP, AH, ...): a
         * valid frame, just not UDP. */
        out->next_header = next_header;
        return CF_DECAP_NOT_UDP;
    }

    return CF_DECAP_UNSUPPORTED; /* extension header chain too deep */
}

cf_decap_result_t cf_decap_udp(const uint8_t *frame, size_t frame_len,
                               cf_decap_udp_t *out)
{
    uint16_t ethertype;
    size_t offset;

    memset(out, 0, sizeof(*out));

    if (remain(frame_len, 0) < ETH_HDR_LEN)
        return CF_DECAP_TRUNCATED;

    memcpy(out->dst_mac, frame, 6);
    memcpy(out->src_mac, frame + 6, 6);
    ethertype = read_u16(frame + 12);
    offset = ETH_HDR_LEN;

    for (int i = 0; i < 2; i++) {
        uint16_t tci, inner_ethertype;

        if (ethertype != ETHERTYPE_VLAN && ethertype != ETHERTYPE_QINQ)
            break;

        if (remain(frame_len, offset) < VLAN_TAG_LEN)
            return CF_DECAP_TRUNCATED;

        tci = read_u16(frame + offset);
        inner_ethertype = read_u16(frame + offset + 2);

        out->vlan_ids[out->vlan_count++] = tci & 0x0FFFu;
        ethertype = inner_ethertype;
        offset += VLAN_TAG_LEN;
    }

    if (ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_QINQ)
        return CF_DECAP_UNSUPPORTED; /* more than 2 VLAN tags */

    out->ethertype = ethertype;

    if (ethertype == ETHERTYPE_IPV4)
        return parse_ipv4(frame, frame_len, offset, out);
    if (ethertype == ETHERTYPE_IPV6)
        return parse_ipv6(frame, frame_len, offset, out);

    return CF_DECAP_UNSUPPORTED; /* not IPv4/IPv6 */
}
