#ifndef CF_DECAP_H
#define CF_DECAP_H

#include <stddef.h>
#include <stdint.h>

/* Ethernet -> (up to 2 VLAN tags) -> IPv4/IPv6 -> UDP/TCP decapsulation.
 *
 * Pure computation: no sockets, no allocation, no globals -- safe to call
 * from any thread on any buffer (kernel rx-ring frame or a pcap-replayed
 * one). Every multi-byte field is read via memcpy plus an explicit
 * byte-order conversion; this code never dereferences a pointer cast into
 * the frame, so it has no alignment/strict-aliasing UB regardless of how
 * the frame buffer itself is aligned.
 *
 * cf_decap_udp() (WP-05) and cf_decap_tcp() (WP-DNS02) share one internal
 * Ethernet+VLAN+IPv4/IPv6 walk that stops at the L4 boundary; each is a thin
 * wrapper that parses its own transport header. cf_decap_tcp() decodes only a
 * single captured TCP segment -- there is no reassembly (see docs/dns-source.md
 * DNS-D1) -- and exposes the raw TCP payload without interpreting any
 * application framing (e.g. the DNS-over-TCP 2-byte length prefix).
 *
 * See docs/dhcp-source.md (WP-05) and docs/dns-source.md (WP-DNS02) for the
 * authoritative spec this header implements verbatim.
 */

typedef struct {
    /* link */
    uint8_t  src_mac[6], dst_mac[6];
    uint32_t vlan_ids[2];
    uint8_t  vlan_count;
    uint16_t ethertype;              /* inner, after VLAN tags */
    /* network */
    uint8_t  ip_version;             /* 4 or 6 */
    uint8_t  src_ip[16], dst_ip[16]; /* v4 in first 4 bytes */
    uint8_t  next_header;            /* protocol / next-header */
    uint8_t  ttl_or_hop_limit;
    uint8_t  dscp, ecn;
    uint8_t  fragmented;             /* first-fragment or fragmented flag set */
    uint16_t fragment_offset;
    /* transport (UDP only in v0.1) */
    uint16_t src_port, dst_port;
    uint16_t udp_length;
    uint8_t  udp_checksum_present;
    /* payload view into the input frame (no copy) */
    const uint8_t *payload;
    size_t payload_len;
} cf_decap_udp_t;

/* Same link+network fields as cf_decap_udp_t, with the TCP transport view in
 * place of the UDP one. Populated by cf_decap_tcp() for a single captured TCP
 * segment; the payload view is the raw TCP payload (no reassembly, no
 * application-layer interpretation). */
typedef struct {
    /* link */
    uint8_t  src_mac[6], dst_mac[6];
    uint32_t vlan_ids[2];
    uint8_t  vlan_count;
    uint16_t ethertype;              /* inner, after VLAN tags */
    /* network */
    uint8_t  ip_version;             /* 4 or 6 */
    uint8_t  src_ip[16], dst_ip[16]; /* v4 in first 4 bytes */
    uint8_t  next_header;            /* protocol / next-header */
    uint8_t  ttl_or_hop_limit;
    uint8_t  dscp, ecn;
    uint8_t  fragmented;             /* first-fragment or fragmented flag set */
    uint16_t fragment_offset;
    /* transport (TCP) */
    uint16_t src_port, dst_port;
    uint32_t seq;                    /* 32-bit sequence number */
    uint8_t  tcp_flags;              /* raw flags byte: FIN/SYN/RST/PSH/ACK/... */
    /* payload view into the input frame (no copy): bytes after the TCP
     * header, bounded by the IP total-length / IPv6 payload-length */
    const uint8_t *payload;
    size_t payload_len;
} cf_decap_tcp_t;

typedef enum {
    CF_DECAP_OK = 0,
    CF_DECAP_NOT_UDP,        /* valid frame, not UDP (or fragmented non-first) */
    CF_DECAP_TRUNCATED,      /* frame shorter than headers claim */
    CF_DECAP_UNSUPPORTED,    /* not IPv4/IPv6, >2 VLAN tags, IPv6 ext chain too deep */
    CF_DECAP_NOT_TCP,        /* valid frame, not TCP (or fragmented non-first) */
} cf_decap_result_t;

cf_decap_result_t cf_decap_udp(const uint8_t *frame, size_t frame_len,
                               cf_decap_udp_t *out);

/* Decapsulate a single captured TCP segment. Reuses the same Ethernet+VLAN+
 * IPv4/IPv6 walk as cf_decap_udp(); on a TCP first-fragment/non-fragmented
 * frame it fills the transport fields and a raw-payload view. Non-TCP or a
 * non-first fragment yields CF_DECAP_NOT_TCP; truncation yields
 * CF_DECAP_TRUNCATED; unsupported shapes yield CF_DECAP_UNSUPPORTED. */
cf_decap_result_t cf_decap_tcp(const uint8_t *frame, size_t frame_len,
                               cf_decap_tcp_t *out);

#endif
