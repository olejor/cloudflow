/* libs/cloudflow-packet/cf_decap.c
 *
 * Ethernet -> (up to 2 VLAN tags) -> IPv4/IPv6 -> UDP/TCP decapsulation. See
 * cf_decap.h, docs/dhcp-source.md (WP-05, UDP), and docs/dns-source.md
 * (WP-DNS02, single-segment TCP) for the contract.
 *
 * The Ethernet+VLAN+IPv4/IPv6 header walk is shared: decap_walk() resolves
 * every link and network field and stops AT the L4 header boundary, reporting
 * the L4 offset, the L4 protocol, and whether an L4 header is actually present
 * here (it is not, for a non-first fragment). cf_decap_udp() and
 * cf_decap_tcp() are thin wrappers that run that walk and then parse their own
 * transport header.
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

#define IP_PROTO_TCP       6u
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
#define TCP_MIN_HDR_LEN 20u

/* Max number of IPv6 extension headers (hop-by-hop/dest-options/routing/
 * fragment) walked while looking for the L4 header, per the WP-05 spec. */
#define IPV6_MAX_EXT_HEADERS 8

/* Result of the shared Ethernet+VLAN+IPv4/IPv6 walk: every link and network
 * field, plus where the L4 header starts and whether one is present. The
 * public cf_decap_udp_t/cf_decap_tcp_t structs mirror the link+network block;
 * the wrappers copy it out and then parse the transport header themselves. */
typedef struct {
    /* link */
    uint8_t  src_mac[6], dst_mac[6];
    uint32_t vlan_ids[2];
    uint8_t  vlan_count;
    uint16_t ethertype;
    /* network */
    uint8_t  ip_version;
    uint8_t  src_ip[16], dst_ip[16];
    uint8_t  next_header;            /* L4 protocol / IPv6 final next-header */
    uint8_t  ttl_or_hop_limit;
    uint8_t  dscp, ecn;
    uint8_t  fragmented;
    uint16_t fragment_offset;
    /* L4 boundary */
    size_t   l4_offset;              /* start of the L4 header (iff l4_present) */
    size_t   ip_payload_end;         /* end of the IP payload, clamped to frame_len */
    uint8_t  l4_present;             /* 0 for a non-first fragment (no L4 header here) */
} cf_decap_walk_t;

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

/* Parses the TCP header at `frame[offset..]` into `out`, including the raw
 * payload view. `ip_payload_end` is the end of the IP payload (from the IPv4
 * total-length / IPv6 payload-length, already clamped to frame_len by the
 * walk); the payload runs from the end of the TCP header to there. Requires
 * the caller to have established that `offset` is the start of a TCP header
 * for a non-fragmented-or-first fragment (fragmentation bookkeeping is done by
 * the walk). Does not interpret any application framing above TCP. */
static cf_decap_result_t parse_tcp(const uint8_t *frame, size_t frame_len,
                                    size_t offset, size_t ip_payload_end,
                                    cf_decap_tcp_t *out)
{
    uint8_t data_offset_byte, flags;
    size_t  data_offset, payload_start, payload_end;

    if (remain(frame_len, offset) < TCP_MIN_HDR_LEN)
        return CF_DECAP_TRUNCATED;

    out->src_port    = read_u16(frame + offset);
    out->dst_port    = read_u16(frame + offset + 2);
    out->seq         = read_u32(frame + offset + 4);
    data_offset_byte = frame[offset + 12];
    flags            = frame[offset + 13];

    /* Data offset is the header length in 32-bit words (high nibble of byte
     * 12). It must be at least the 20-byte minimum and fit in the captured
     * bytes -- a header claiming to run past the segment is truncation. */
    data_offset = (size_t)(data_offset_byte >> 4) * 4u;
    if (data_offset < TCP_MIN_HDR_LEN)
        return CF_DECAP_TRUNCATED; /* header claims a length shorter than itself */
    if (remain(frame_len, offset) < data_offset)
        return CF_DECAP_TRUNCATED; /* header runs past the captured bytes */

    out->tcp_flags = flags; /* raw FIN/SYN/RST/PSH/ACK/... byte */

    /* Payload = bytes after the TCP header through the end of the IP payload,
     * never past frame_len (ip_payload_end is already clamped) and never
     * before payload_start if the IP length is implausibly small. */
    payload_start = offset + data_offset;
    payload_end   = ip_payload_end;
    if (payload_end < payload_start)
        payload_end = payload_start;
    if (payload_end > frame_len)
        payload_end = frame_len;

    out->payload     = frame + payload_start;
    out->payload_len = payload_end - payload_start;

    return CF_DECAP_OK;
}

/* Walks the IPv4 header at `frame[offset..]`, filling `w`'s network fields and
 * resolving the L4 boundary. Stops at the L4 header without parsing it. */
static cf_decap_result_t walk_ipv4(const uint8_t *frame, size_t frame_len,
                                    size_t offset, cf_decap_walk_t *w)
{
    uint8_t version_ihl, tos, ttl, protocol;
    uint16_t total_len, flags_frag;
    size_t ihl;

    if (remain(frame_len, offset) < IPV4_MIN_HDR_LEN)
        return CF_DECAP_TRUNCATED;

    version_ihl = frame[offset];
    if ((version_ihl >> 4) != 4)
        return CF_DECAP_UNSUPPORTED; /* ethertype said v4 but header disagrees */

    ihl = (size_t)(version_ihl & 0x0Fu) * 4u;
    if (ihl < IPV4_MIN_HDR_LEN || remain(frame_len, offset) < ihl)
        return CF_DECAP_TRUNCATED;

    tos        = frame[offset + 1];
    total_len  = read_u16(frame + offset + 2);
    flags_frag = read_u16(frame + offset + 6);
    ttl        = frame[offset + 8];
    protocol   = frame[offset + 9];

    w->ip_version = 4;
    memcpy(w->src_ip, frame + offset + 12, 4);
    memcpy(w->dst_ip, frame + offset + 16, 4);
    w->next_header       = protocol;
    w->ttl_or_hop_limit  = ttl;
    w->dscp              = (uint8_t)(tos >> 2);
    w->ecn               = (uint8_t)(tos & 0x3u);

    /* End of the IP payload from total-length, clamped so an implausible or
     * capture-truncated length can never push a payload view past frame_len. */
    {
        size_t end = offset + total_len;
        if (total_len < ihl || end > frame_len)
            end = frame_len;
        w->ip_payload_end = end;
    }

    {
        uint16_t frag_offset13 = flags_frag & 0x1FFFu;
        uint8_t  more_fragments = (flags_frag & 0x2000u) != 0;

        w->fragment_offset = frag_offset13;

        if (frag_offset13 != 0) {
            /* non-first fragment: no L4 header present here */
            w->fragmented = 1;
            w->l4_present = 0;
            return CF_DECAP_OK;
        }

        w->fragmented = more_fragments;
    }

    w->l4_offset  = offset + ihl;
    w->l4_present = 1;
    return CF_DECAP_OK;
}

/* Walks the IPv6 header (and any extension-header chain) at `frame[offset..]`,
 * filling `w`'s network fields and resolving the L4 boundary. Stops at the L4
 * header without parsing it. */
static cf_decap_result_t walk_ipv6(const uint8_t *frame, size_t frame_len,
                                    size_t offset, cf_decap_walk_t *w)
{
    uint32_t word0;
    uint8_t version, traffic_class, next_header, hop_limit;
    uint16_t payload_len;
    size_t cur_offset, end;
    int i;

    if (remain(frame_len, offset) < IPV6_FIXED_HDR_LEN)
        return CF_DECAP_TRUNCATED;

    word0 = read_u32(frame + offset);
    version       = (uint8_t)(word0 >> 28);
    traffic_class = (uint8_t)((word0 >> 20) & 0xFFu);
    if (version != 6)
        return CF_DECAP_UNSUPPORTED;

    payload_len = read_u16(frame + offset + 4);
    next_header = frame[offset + 6];
    hop_limit   = frame[offset + 7];

    w->ip_version = 6;
    memcpy(w->src_ip, frame + offset + 8, 16);
    memcpy(w->dst_ip, frame + offset + 24, 16);
    w->ttl_or_hop_limit = hop_limit;
    w->dscp             = (uint8_t)(traffic_class >> 2);
    w->ecn              = (uint8_t)(traffic_class & 0x3u);
    w->next_header      = next_header;

    /* Payload-length covers everything after the fixed header (extension
     * headers included); clamp its end to frame_len. */
    end = offset + IPV6_FIXED_HDR_LEN + payload_len;
    if (end > frame_len)
        end = frame_len;
    w->ip_payload_end = end;

    cur_offset = offset + IPV6_FIXED_HDR_LEN;

    for (i = 0; i < IPV6_MAX_EXT_HEADERS; i++) {
        if (next_header == IPV6_PROTO_FRAGMENT) {
            uint16_t off_res_m;
            uint8_t  frag_next_header;
            uint16_t frag_offset13;

            if (remain(frame_len, cur_offset) < IPV6_FRAG_HDR_LEN)
                return CF_DECAP_TRUNCATED;

            frag_next_header = frame[cur_offset];
            off_res_m        = read_u16(frame + cur_offset + 2);
            frag_offset13    = off_res_m >> 3;

            w->next_header      = frag_next_header;
            w->fragment_offset  = frag_offset13;

            if (frag_offset13 != 0) {
                /* non-first fragment: no L4 header present here */
                w->fragmented = 1;
                w->l4_present = 0;
                return CF_DECAP_OK;
            }

            w->fragmented = 1;
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

            w->next_header = ext_next_header;
            next_header = ext_next_header;
            cur_offset += ext_total_len;
            continue;
        }

        /* Reached the L4 header: UDP, TCP, ICMPv6, ESP, AH, ... Whatever it
         * is, a header is present here; the wrapper decides if it is the one
         * it wants. */
        w->next_header  = next_header;
        w->l4_offset    = cur_offset;
        w->l4_present   = 1;
        return CF_DECAP_OK;
    }

    return CF_DECAP_UNSUPPORTED; /* extension header chain too deep */
}

/* Shared Ethernet -> (up to 2 VLAN tags) -> IPv4/IPv6 walk. On CF_DECAP_OK,
 * `w` holds every resolved link+network field plus the L4 boundary; the
 * transport is left to the caller. CF_DECAP_TRUNCATED/CF_DECAP_UNSUPPORTED are
 * returned exactly as before. */
static cf_decap_result_t decap_walk(const uint8_t *frame, size_t frame_len,
                                     cf_decap_walk_t *w)
{
    uint16_t ethertype;
    size_t offset;

    memset(w, 0, sizeof(*w));

    if (remain(frame_len, 0) < ETH_HDR_LEN)
        return CF_DECAP_TRUNCATED;

    memcpy(w->dst_mac, frame, 6);
    memcpy(w->src_mac, frame + 6, 6);
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

        w->vlan_ids[w->vlan_count++] = tci & 0x0FFFu;
        ethertype = inner_ethertype;
        offset += VLAN_TAG_LEN;
    }

    if (ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_QINQ)
        return CF_DECAP_UNSUPPORTED; /* more than 2 VLAN tags */

    w->ethertype = ethertype;

    if (ethertype == ETHERTYPE_IPV4)
        return walk_ipv4(frame, frame_len, offset, w);
    if (ethertype == ETHERTYPE_IPV6)
        return walk_ipv6(frame, frame_len, offset, w);

    return CF_DECAP_UNSUPPORTED; /* not IPv4/IPv6 */
}

/* Copies the shared link+network block the walk resolved into a UDP result. */
static void copy_l3_udp(cf_decap_udp_t *out, const cf_decap_walk_t *w)
{
    memcpy(out->src_mac, w->src_mac, 6);
    memcpy(out->dst_mac, w->dst_mac, 6);
    out->vlan_ids[0] = w->vlan_ids[0];
    out->vlan_ids[1] = w->vlan_ids[1];
    out->vlan_count  = w->vlan_count;
    out->ethertype   = w->ethertype;
    out->ip_version  = w->ip_version;
    memcpy(out->src_ip, w->src_ip, 16);
    memcpy(out->dst_ip, w->dst_ip, 16);
    out->next_header      = w->next_header;
    out->ttl_or_hop_limit = w->ttl_or_hop_limit;
    out->dscp             = w->dscp;
    out->ecn              = w->ecn;
    out->fragmented       = w->fragmented;
    out->fragment_offset  = w->fragment_offset;
}

/* Copies the shared link+network block the walk resolved into a TCP result. */
static void copy_l3_tcp(cf_decap_tcp_t *out, const cf_decap_walk_t *w)
{
    memcpy(out->src_mac, w->src_mac, 6);
    memcpy(out->dst_mac, w->dst_mac, 6);
    out->vlan_ids[0] = w->vlan_ids[0];
    out->vlan_ids[1] = w->vlan_ids[1];
    out->vlan_count  = w->vlan_count;
    out->ethertype   = w->ethertype;
    out->ip_version  = w->ip_version;
    memcpy(out->src_ip, w->src_ip, 16);
    memcpy(out->dst_ip, w->dst_ip, 16);
    out->next_header      = w->next_header;
    out->ttl_or_hop_limit = w->ttl_or_hop_limit;
    out->dscp             = w->dscp;
    out->ecn              = w->ecn;
    out->fragmented       = w->fragmented;
    out->fragment_offset  = w->fragment_offset;
}

cf_decap_result_t cf_decap_udp(const uint8_t *frame, size_t frame_len,
                               cf_decap_udp_t *out)
{
    cf_decap_walk_t w;
    cf_decap_result_t rc;

    memset(out, 0, sizeof(*out));

    rc = decap_walk(frame, frame_len, &w);
    copy_l3_udp(out, &w);
    if (rc != CF_DECAP_OK)
        return rc;

    /* A non-first fragment has no L4 header here; a non-UDP protocol is a
     * valid frame that simply is not UDP. */
    if (!w.l4_present || w.next_header != IP_PROTO_UDP)
        return CF_DECAP_NOT_UDP;

    return parse_udp(frame, frame_len, w.l4_offset, out);
}

cf_decap_result_t cf_decap_tcp(const uint8_t *frame, size_t frame_len,
                               cf_decap_tcp_t *out)
{
    cf_decap_walk_t w;
    cf_decap_result_t rc;

    memset(out, 0, sizeof(*out));

    rc = decap_walk(frame, frame_len, &w);
    copy_l3_tcp(out, &w);
    if (rc != CF_DECAP_OK)
        return rc;

    /* A non-first fragment has no L4 header here; a non-TCP protocol is a
     * valid frame that simply is not TCP. */
    if (!w.l4_present || w.next_header != IP_PROTO_TCP)
        return CF_DECAP_NOT_TCP;

    return parse_tcp(frame, frame_len, w.l4_offset, w.ip_payload_end, out);
}
