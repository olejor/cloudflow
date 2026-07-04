#ifndef CF_DHCPV4_H
#define CF_DHCPV4_H

#include <stddef.h>
#include <stdint.h>

#include "cloudflow/v1/dhcp.pb-c.h"

/* DHCPv4 parser (WP-06). Pure computation: the UDP payload in -> a
 * heap-allocated Cloudflow__V1__DhcpV4PacketEvent tree out. No sockets, no
 * Redis, no threads. See docs/dhcp-source.md ("Shared
 * parser conventions" and the WP-06 section) for the authoritative spec
 * this implements.
 *
 * The returned message tree is built directly (not via protobuf-c's
 * ...__unpack()), but every nested message is allocated with calloc() and
 * initialized via its generated `..._init()` function, and every repeated
 * field's backing array is a plain malloc()'d array of the type the
 * generated struct expects. That is enough for the generated, fully
 * descriptor-driven `cloudflow__v1__dhcp_v4_packet_event__free_unpacked()`
 * to walk and free the whole tree correctly regardless of how it was built
 * -- which is exactly what cf_dhcpv4_event_free() below does.
 */

/* Parses a DHCPv4/BOOTP payload (the bytes immediately following the UDP
 * header -- this function never sees Ethernet/IP/UDP framing).
 *
 * Returns NULL only on allocation failure or if `len` is too short to
 * contain the fixed BOOTP header (236 bytes, op..file; the options are
 * a separate, always-optional area starting at offset 240). Never returns
 * NULL for a malformed-but-header-sized payload: malformed options are
 * reported via `parser_warnings` and the corresponding DhcpV4Option's
 * `malformed` flag, and parsing continues at the best available resync
 * point (see the option-walk comments in cf_dhcpv4.c). No input, however
 * corrupt, causes a crash or out-of-bounds read.
 *
 * On success, `*event_type` (if non-NULL) receives a pointer to a static
 * string (e.g. "dhcpv4.discover.observed") giving the caller the derived
 * event type without having to re-derive it from `interpretation`. On
 * failure `*event_type` (if non-NULL) is set to NULL.
 *
 * The `packet` field (PacketObservation) of the returned event is left
 * NULL -- the caller (the WP-10 event formatter) attaches it, since this
 * library never sees link/network layer metadata.
 */
Cloudflow__V1__DhcpV4PacketEvent *
cf_dhcpv4_parse(const uint8_t *payload, size_t len, const char **event_type);

/* Frees a tree returned by cf_dhcpv4_parse(). Safe to call with NULL. */
void cf_dhcpv4_event_free(Cloudflow__V1__DhcpV4PacketEvent *ev);

#endif
