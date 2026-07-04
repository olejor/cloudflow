#ifndef CF_SOURCE_DHCP_DHCP_BPF_H
#define CF_SOURCE_DHCP_DHCP_BPF_H

/* The DHCP-specific cBPF filter leaf: a VLAN-aware program matching UDP with
 * a DHCP src OR dst port (67/68 for DHCPv4, 546/547 for DHCPv6). Built on
 * libs/cloudflow-capture's shared two-pass assembler and UDP/VLAN-offset
 * primitives (cf_bpf.h) -- this file only lays out the ethertype/VLAN
 * dispatch and picks the ports; all the delicate offset/jump machinery lives
 * once, in the capture library.
 *
 * The assembled program is byte-for-byte identical to the filter the DHCP
 * source shipped before this leaf was split out of rx_reader.c; see
 * tests/dhcp_bpf_test.c, which asserts it against a golden capture. */

#include <linux/filter.h> /* struct sock_filter */

/* Builds the VLAN-aware DHCP filter into `out` (capacity `max` instructions).
 * Returns the instruction count on success, -1 on assembler failure (which
 * can only happen if this function itself has a bug -- there is no
 * runtime-variable input to the program). */
int build_dhcp_bpf_filter(struct sock_filter *out, int max);

#endif
