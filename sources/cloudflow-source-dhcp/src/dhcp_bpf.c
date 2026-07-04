#include "dhcp_bpf.h"

#include <string.h>

#include <linux/if_ether.h> /* ETH_P_8021Q, ETH_P_IP, ETH_P_IPV6 */

#include "cf_bpf.h"

/* Filter layout: match the EtherType at offset 12; if it is 802.1Q, re-read
 * the real EtherType past the 4-byte tag at offset 16 and use IP-header base
 * 18, otherwise use base 14. Each {v4,v6} x {untagged,tagged} branch is a
 * separate copy so every fixed offset is correct for the frame it applies to
 * (the VLAN-offset correctness the shared cf_bpf primitives exist to protect).
 * Only a single VLAN tag is unwrapped; QinQ/double-tagging is out of scope. */

enum {
    BPF_LBL_VLAN = 0,
    BPF_LBL_IP4_14,
    BPF_LBL_IP6_14,
    BPF_LBL_IP4_18,
    BPF_LBL_IP6_18,
    BPF_LBL_ACCEPT,
    BPF_LBL_DROP,
};

/* DHCP UDP ports. */
#define DHCPV4_PORT_A 67
#define DHCPV4_PORT_B 68
#define DHCPV6_PORT_A 546
#define DHCPV6_PORT_B 547

int build_dhcp_bpf_filter(struct sock_filter *out, int max)
{
    bpf_asm_t a;

    bpf_asm_init(&a);

    /* EtherType at offset 12, assuming no VLAN tag. */
    bpf_asm_stmt(&a, BPF_LD | BPF_H | BPF_ABS, 12);
    bpf_asm_jump(&a, BPF_JMP | BPF_JEQ | BPF_K, ETH_P_8021Q, BPF_LBL_VLAN, CF_BPF_ASM_FALLTHROUGH);
    bpf_asm_jump(&a, BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IP, BPF_LBL_IP4_14, CF_BPF_ASM_FALLTHROUGH);
    bpf_asm_jump(&a, BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IPV6, BPF_LBL_IP6_14, BPF_LBL_DROP);

    bpf_asm_label(&a, BPF_LBL_VLAN);
    bpf_asm_stmt(&a, BPF_LD | BPF_H | BPF_ABS, 16); /* real EtherType past the VLAN tag */
    bpf_asm_jump(&a, BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IP, BPF_LBL_IP4_18, CF_BPF_ASM_FALLTHROUGH);
    bpf_asm_jump(&a, BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IPV6, BPF_LBL_IP6_18, BPF_LBL_DROP);

    bpf_asm_label(&a, BPF_LBL_IP4_14);
    bpf_asm_ipv4_udp_ports_branch(&a, 14, DHCPV4_PORT_A, DHCPV4_PORT_B, BPF_LBL_ACCEPT, BPF_LBL_DROP);

    bpf_asm_label(&a, BPF_LBL_IP6_14);
    bpf_asm_ipv6_udp_ports_branch(&a, 14, DHCPV6_PORT_A, DHCPV6_PORT_B, BPF_LBL_ACCEPT, BPF_LBL_DROP);

    bpf_asm_label(&a, BPF_LBL_IP4_18);
    bpf_asm_ipv4_udp_ports_branch(&a, 18, DHCPV4_PORT_A, DHCPV4_PORT_B, BPF_LBL_ACCEPT, BPF_LBL_DROP);

    bpf_asm_label(&a, BPF_LBL_IP6_18);
    bpf_asm_ipv6_udp_ports_branch(&a, 18, DHCPV6_PORT_A, DHCPV6_PORT_B, BPF_LBL_ACCEPT, BPF_LBL_DROP);

    bpf_asm_label(&a, BPF_LBL_ACCEPT);
    bpf_asm_stmt(&a, BPF_RET | BPF_K, (__u32)-1);

    bpf_asm_label(&a, BPF_LBL_DROP);
    bpf_asm_stmt(&a, BPF_RET | BPF_K, 0);

    if (bpf_asm_finish(&a) != 0)
        return -1;

    if (a.n > max)
        return -1;

    memcpy(out, a.insns, (size_t)a.n * sizeof(a.insns[0]));

    return a.n;
}
