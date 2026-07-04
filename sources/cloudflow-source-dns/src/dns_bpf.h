#ifndef CF_SOURCE_DNS_DNS_BPF_H
#define CF_SOURCE_DNS_DNS_BPF_H

/* The DNS-specific cBPF filter leaf (WP-DNS06): a VLAN-aware program that
 * accepts a frame iff it is IPv4 or IPv6 carrying UDP or TCP with source OR
 * destination port 53 (udp/53 + tcp/53 only -- DNS-D1; no DoH/DoT/DoQ).
 * Everything else -- other L4 protocols, other ports, non-IP ethertypes, and
 * non-first IP fragments (which carry no transport header to read a port from)
 * -- is dropped kernel-side before it ever reaches userspace.
 *
 * Built on libs/cloudflow-capture's shared two-pass cBPF assembler and its
 * UDP/TCP/VLAN-offset primitives (cf_bpf.h): this file only lays out the
 * ethertype/VLAN dispatch, picks port 53, and chains "try UDP:53, else try
 * TCP:53, else drop" per IP version. The delicate offset/jump machinery lives
 * once, in the capture library, exactly like the DHCP filter leaf
 * (sources/cloudflow-source-dhcp/src/dhcp_bpf.c). */

#include <linux/filter.h> /* struct sock_filter */

/* Builds the VLAN-aware DNS filter into `out` (capacity `max` instructions).
 * Returns the instruction count on success, -1 on assembler failure or if the
 * program does not fit in `max` (a bug in this function -- there is no
 * runtime-variable input to the program). */
int build_dns_bpf_filter(struct sock_filter *out, int max);

/* Convenience wrapper: assembles the filter into `out` and, on success, points
 * the two cf_rx_reader_config_t fields at it -- call as
 *
 *     struct sock_filter prog[DNS_BPF_MAX_INSNS];
 *     cf_rx_reader_config_t cfg = { ... };
 *     if (build_dns_bpf_filter_config(prog, DNS_BPF_MAX_INSNS,
 *                                     &cfg.bpf, &cfg.bpf_len) < 0)
 *         return -1;  // then cf_rx_reader_start(&cfg)
 *
 * The `bpf`/`bpf_len` out-params mirror cf_rx_reader_config_t's fields exactly
 * (const struct sock_filter *, unsigned short) so this header need not pull in
 * cf_rx_reader.h. `out` must outlive the reader. Returns the instruction count
 * or -1. Either out-param may be NULL. */
int build_dns_bpf_filter_config(struct sock_filter *out, int max,
                                const struct sock_filter **bpf_out,
                                unsigned short *bpf_len_out);

/* A comfortable upper bound for the assembled program size; the current filter
 * is well under this and under cf_bpf's CF_BPF_ASM_MAX_INSNS. */
#define DNS_BPF_MAX_INSNS 128

#endif
