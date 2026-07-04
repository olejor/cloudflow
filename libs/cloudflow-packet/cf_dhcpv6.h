#ifndef CF_DHCPV6_H
#define CF_DHCPV6_H

#include <stddef.h>
#include <stdint.h>

#include "cloudflow/v1/dhcp.pb-c.h"

/* DHCPv6 parser (WP-07). Pure computation: the UDP payload in -> a
 * heap-allocated Cloudflow__V1__DhcpV6PacketEvent tree out. No sockets, no
 * Redis, no threads. See docs/dhcp-source.md ("Shared
 * parser conventions" and the WP-07 section) for the authoritative spec
 * this implements; mirrors the WP-06 DHCPv4 parser's API and construction
 * style (see cf_dhcpv4.h's header comment for the "built directly, not via
 * ...__unpack(), but every nested message/repeated-field array is
 * calloc()/malloc()'d exactly as the generated free_unpacked() expects"
 * contract -- identical here).
 */

/* Parses a DHCPv6 payload (the bytes immediately following the UDP header --
 * this function never sees Ethernet/IP/UDP framing, and never sees the
 * frame the inner message of a relayed exchange was itself relayed in).
 *
 * Returns NULL only on allocation failure or if `len` is shorter than the
 * 4-byte fixed header every DHCPv6 message starts with (1 byte msg-type +
 * either a 3-byte transaction-id for client/server messages, or the first
 * byte of hop-count/link-address for RELAY-FORW/RELAY-REPL messages, whose
 * own additional 33 bytes of fixed relay fields are read with their own
 * bounds checks -- a relay message truncated past byte 4 still parses,
 * with link_address/peer_address left at their proto3 default ""). Never
 * returns NULL for a malformed-but-header-sized payload: malformed options
 * are reported via `parser_warnings` and the corresponding DhcpV6Option's
 * `malformed` flag, and parsing continues at the best available resync
 * point. No input, however corrupt, causes a crash or out-of-bounds read.
 *
 * On success, `*event_type` (if non-NULL) receives a pointer to a static
 * string (e.g. "dhcpv6.solicit.observed", "dhcpv6.relay-forw.observed")
 * giving the caller the derived event type. On failure `*event_type` (if
 * non-NULL) is set to NULL.
 *
 * For RELAY-FORW/RELAY-REPL messages, only the *outer* message's options
 * are walked into raw_options/decoded; the inner client/server message
 * carried in the Relay Message option (code 9) appears verbatim as that
 * option's raw bytes -- recursive inner parsing is a later enhancement
 * (see docs/dhcp-source.md's WP-07 section).
 *
 * The `packet` field (PacketObservation) of the returned event is left
 * NULL -- the caller (the WP-10 event formatter) attaches it, since this
 * library never sees link/network layer metadata.
 */
Cloudflow__V1__DhcpV6PacketEvent *
cf_dhcpv6_parse(const uint8_t *payload, size_t len, const char **event_type);

/* Frees a tree returned by cf_dhcpv6_parse(). Safe to call with NULL. */
void cf_dhcpv6_event_free(Cloudflow__V1__DhcpV6PacketEvent *ev);

#endif
