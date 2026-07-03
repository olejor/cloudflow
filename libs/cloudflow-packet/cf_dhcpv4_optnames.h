#ifndef CF_DHCPV4_OPTNAMES_H
#define CF_DHCPV4_OPTNAMES_H

#include <stdint.h>

/* Canonical DHCPv4 option-code -> name table, sourced from the IANA
 * "BOOTP Vendor Extensions and DHCP Options" registry. Unknown codes return
 * "" (never a guess), per docs/dhcp-source.md's "Shared
 * parser conventions".
 *
 * The returned pointer is to a static string literal; callers that need an
 * owned copy must duplicate it themselves (cf_dhcpv4.c always does, since
 * the protobuf-c DhcpV4Option.name field owns its string).
 */
const char *cf_dhcpv4_option_name(uint32_t code);

#endif
