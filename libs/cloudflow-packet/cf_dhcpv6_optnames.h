#ifndef CF_DHCPV6_OPTNAMES_H
#define CF_DHCPV6_OPTNAMES_H

#include <stdint.h>

/* Canonical DHCPv6 option-code -> name table, sourced from the IANA
 * "DHCPv6 Option Codes" registry. Unknown codes return "" (never a guess),
 * per docs/dhcp-source.md's "Shared parser conventions".
 *
 * The returned pointer is to a static string literal; callers that need an
 * owned copy must duplicate it themselves (cf_dhcpv6.c always does, since
 * the protobuf-c DhcpV6Option.name field owns its string).
 */
const char *cf_dhcpv6_option_name(uint32_t code);

#endif
