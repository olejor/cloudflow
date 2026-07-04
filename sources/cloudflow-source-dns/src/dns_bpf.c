#include "dns_bpf.h"

#include <string.h>

#include <linux/if_ether.h> /* ETH_P_8021Q, ETH_P_IP, ETH_P_IPV6 */

/* The shared two-pass cBPF assembler + VLAN-aware branch primitives, linked
 * from libcloudflow-capture.a (the DNS Makefile links the capture lib,
 * mirroring the DHCP source). This DNS filter leaf and the DHCP one both build
 * on the same single, tested cf_bpf implementation. */
#include "cf_bpf.h"

/* DNS transport port (DNS-D1: udp/53 and tcp/53 only). The cf_bpf two-port
 * primitives match src OR dst against two ports; DNS has a single well-known
 * port, so both are 53 (the redundant second compare costs one instruction per
 * port position and keeps the shared primitive contract unchanged). */
#define DNS_PORT 53

/* Filter layout mirrors the DHCP leaf: match the EtherType at offset 12; if it
 * is 802.1Q, re-read the real EtherType past the 4-byte tag at offset 16 and
 * use IP-header base 18, otherwise base 14. Each {v4,v6} x {untagged,tagged}
 * branch is a separate copy so every fixed offset is correct for the frame it
 * applies to. Per IP version we chain transports: try the UDP:53 branch, on any
 * mismatch fall into the TCP:53 branch, and on ITS mismatch drop. Only a single
 * VLAN tag is unwrapped; QinQ/double-tagging is out of scope. */
enum {
    DNS_LBL_VLAN = 0,
    DNS_LBL_IP4_14,
    DNS_LBL_TCP4_14,
    DNS_LBL_IP6_14,
    DNS_LBL_TCP6_14,
    DNS_LBL_IP4_18,
    DNS_LBL_TCP4_18,
    DNS_LBL_IP6_18,
    DNS_LBL_TCP6_18,
    DNS_LBL_ACCEPT,
    DNS_LBL_DROP,
};

int build_dns_bpf_filter(struct sock_filter *out, int max)
{
    bpf_asm_t a;

    bpf_asm_init(&a);

    /* EtherType at offset 12, assuming no VLAN tag. */
    bpf_asm_stmt(&a, BPF_LD | BPF_H | BPF_ABS, 12);
    bpf_asm_jump(&a, BPF_JMP | BPF_JEQ | BPF_K, ETH_P_8021Q, DNS_LBL_VLAN, CF_BPF_ASM_FALLTHROUGH);
    bpf_asm_jump(&a, BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IP, DNS_LBL_IP4_14, CF_BPF_ASM_FALLTHROUGH);
    bpf_asm_jump(&a, BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IPV6, DNS_LBL_IP6_14, DNS_LBL_DROP);

    bpf_asm_label(&a, DNS_LBL_VLAN);
    bpf_asm_stmt(&a, BPF_LD | BPF_H | BPF_ABS, 16); /* real EtherType past the VLAN tag */
    bpf_asm_jump(&a, BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IP, DNS_LBL_IP4_18, CF_BPF_ASM_FALLTHROUGH);
    bpf_asm_jump(&a, BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IPV6, DNS_LBL_IP6_18, DNS_LBL_DROP);

    /* Untagged (ip_base 14). */
    bpf_asm_label(&a, DNS_LBL_IP4_14);
    bpf_asm_ipv4_udp_ports_branch(&a, 14, DNS_PORT, DNS_PORT, DNS_LBL_ACCEPT, DNS_LBL_TCP4_14);
    bpf_asm_label(&a, DNS_LBL_TCP4_14);
    bpf_asm_ipv4_tcp_ports_branch(&a, 14, DNS_PORT, DNS_PORT, DNS_LBL_ACCEPT, DNS_LBL_DROP);

    bpf_asm_label(&a, DNS_LBL_IP6_14);
    bpf_asm_ipv6_udp_ports_branch(&a, 14, DNS_PORT, DNS_PORT, DNS_LBL_ACCEPT, DNS_LBL_TCP6_14);
    bpf_asm_label(&a, DNS_LBL_TCP6_14);
    bpf_asm_ipv6_tcp_ports_branch(&a, 14, DNS_PORT, DNS_PORT, DNS_LBL_ACCEPT, DNS_LBL_DROP);

    /* Single 802.1Q tag (ip_base 18). */
    bpf_asm_label(&a, DNS_LBL_IP4_18);
    bpf_asm_ipv4_udp_ports_branch(&a, 18, DNS_PORT, DNS_PORT, DNS_LBL_ACCEPT, DNS_LBL_TCP4_18);
    bpf_asm_label(&a, DNS_LBL_TCP4_18);
    bpf_asm_ipv4_tcp_ports_branch(&a, 18, DNS_PORT, DNS_PORT, DNS_LBL_ACCEPT, DNS_LBL_DROP);

    bpf_asm_label(&a, DNS_LBL_IP6_18);
    bpf_asm_ipv6_udp_ports_branch(&a, 18, DNS_PORT, DNS_PORT, DNS_LBL_ACCEPT, DNS_LBL_TCP6_18);
    bpf_asm_label(&a, DNS_LBL_TCP6_18);
    bpf_asm_ipv6_tcp_ports_branch(&a, 18, DNS_PORT, DNS_PORT, DNS_LBL_ACCEPT, DNS_LBL_DROP);

    bpf_asm_label(&a, DNS_LBL_ACCEPT);
    bpf_asm_stmt(&a, BPF_RET | BPF_K, (__u32)-1);

    bpf_asm_label(&a, DNS_LBL_DROP);
    bpf_asm_stmt(&a, BPF_RET | BPF_K, 0);

    if (bpf_asm_finish(&a) != 0)
        return -1;

    if (a.n > max)
        return -1;

    memcpy(out, a.insns, (size_t)a.n * sizeof(a.insns[0]));

    return a.n;
}

int build_dns_bpf_filter_config(struct sock_filter *out, int max,
                                const struct sock_filter **bpf_out,
                                unsigned short *bpf_len_out)
{
    int n = build_dns_bpf_filter(out, max);

    if (n < 0)
        return -1;

    if (bpf_out)
        *bpf_out = out;
    if (bpf_len_out)
        *bpf_len_out = (unsigned short)n;

    return n;
}
