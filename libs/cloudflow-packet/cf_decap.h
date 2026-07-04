#ifndef CF_DECAP_H
#define CF_DECAP_H

#include <stddef.h>
#include <stdint.h>

/* Ethernet -> (up to 2 VLAN tags) -> IPv4/IPv6 -> UDP decapsulation.
 *
 * Pure computation: no sockets, no allocation, no globals -- safe to call
 * from any thread on any buffer (kernel rx-ring frame or a pcap-replayed
 * one). Every multi-byte field is read via memcpy plus an explicit
 * byte-order conversion; this code never dereferences a pointer cast into
 * the frame, so it has no alignment/strict-aliasing UB regardless of how
 * the frame buffer itself is aligned.
 *
 * See docs/dhcp-source.md (WP-05) for the authoritative
 * spec this header implements verbatim.
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

typedef enum {
    CF_DECAP_OK = 0,
    CF_DECAP_NOT_UDP,        /* valid frame, not UDP (or fragmented non-first) */
    CF_DECAP_TRUNCATED,      /* frame shorter than headers claim */
    CF_DECAP_UNSUPPORTED,    /* not IPv4/IPv6, >2 VLAN tags, IPv6 ext chain too deep */
} cf_decap_result_t;

cf_decap_result_t cf_decap_udp(const uint8_t *frame, size_t frame_len,
                               cf_decap_udp_t *out);

#endif
