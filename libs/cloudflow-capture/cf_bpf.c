#include "cf_bpf.h"

#include <netinet/in.h> /* IPPROTO_UDP */
#include <string.h>

void bpf_asm_init(bpf_asm_t *a)
{
    int i;

    memset(a, 0, sizeof(*a));
    for (i = 0; i < CF_BPF_ASM_MAX_LABELS; i++)
        a->label_pos[i] = -1;
}

void bpf_asm_label(bpf_asm_t *a, int label)
{
    if (label < 0 || label >= CF_BPF_ASM_MAX_LABELS) {
        a->error = 1;
        return;
    }
    a->label_pos[label] = a->n;
}

void bpf_asm_stmt(bpf_asm_t *a, __u16 code, __u32 k)
{
    if (a->n >= CF_BPF_ASM_MAX_INSNS) {
        a->error = 1;
        return;
    }

    a->insns[a->n].code = code;
    a->insns[a->n].jt = 0;
    a->insns[a->n].jf = 0;
    a->insns[a->n].k = k;
    a->n++;
}

void bpf_asm_jump(bpf_asm_t *a, __u16 code, __u32 k, int jt_label, int jf_label)
{
    int idx;

    if (a->n >= CF_BPF_ASM_MAX_INSNS) {
        a->error = 1;
        return;
    }

    idx = a->n;
    a->insns[idx].code = code;
    a->insns[idx].jt = 0;
    a->insns[idx].jf = 0;
    a->insns[idx].k = k;
    a->n++;

    if (jt_label != CF_BPF_ASM_FALLTHROUGH) {
        if (a->n_fixups >= CF_BPF_ASM_MAX_FIXUPS) {
            a->error = 1;
            return;
        }
        a->fixup_insn[a->n_fixups] = idx;
        a->fixup_is_jt[a->n_fixups] = 1;
        a->fixup_label[a->n_fixups] = jt_label;
        a->n_fixups++;
    }

    if (jf_label != CF_BPF_ASM_FALLTHROUGH) {
        if (a->n_fixups >= CF_BPF_ASM_MAX_FIXUPS) {
            a->error = 1;
            return;
        }
        a->fixup_insn[a->n_fixups] = idx;
        a->fixup_is_jt[a->n_fixups] = 0;
        a->fixup_label[a->n_fixups] = jf_label;
        a->n_fixups++;
    }
}

int bpf_asm_finish(bpf_asm_t *a)
{
    int i;

    if (a->error)
        return -1;

    for (i = 0; i < a->n_fixups; i++) {
        int insn_idx = a->fixup_insn[i];
        int label = a->fixup_label[i];
        int target;
        int delta;

        if (label < 0 || label >= CF_BPF_ASM_MAX_LABELS)
            return -1;

        target = a->label_pos[label];
        if (target < 0)
            return -1; /* label never placed */

        delta = target - (insn_idx + 1);
        if (delta < 0 || delta > 255)
            return -1; /* backward jump, or too far for jt/jf's u8 */

        if (a->fixup_is_jt[i])
            a->insns[insn_idx].jt = (__u8)delta;
        else
            a->insns[insn_idx].jf = (__u8)delta;
    }

    return 0;
}

void bpf_asm_check_two_ports(bpf_asm_t *a, __u32 ind_k, __u16 port1, __u16 port2,
                             int accept_label, int final_jf_label)
{
    bpf_asm_stmt(a, BPF_LD | BPF_H | BPF_IND, ind_k);
    bpf_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, port1, accept_label, CF_BPF_ASM_FALLTHROUGH);
    bpf_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, port2, accept_label, final_jf_label);
}

void bpf_asm_ipv4_udp_ports_branch(bpf_asm_t *a, __u32 ip_base, __u16 port1, __u16 port2,
                                    int accept_label, int drop_label)
{
    /* ip.protocol (byte 9 of the IP header) */
    bpf_asm_stmt(a, BPF_LD | BPF_B | BPF_ABS, ip_base + 9);
    bpf_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, CF_BPF_ASM_FALLTHROUGH, drop_label);

    /* flags+fragment-offset (bytes 6-7): reject non-first fragments, same
     * "ip[6:2] & 0x1fff != 0" idiom tcpdump uses. */
    bpf_asm_stmt(a, BPF_LD | BPF_H | BPF_ABS, ip_base + 6);
    bpf_asm_jump(a, BPF_JMP | BPF_JSET | BPF_K, 0x1fffu, drop_label, CF_BPF_ASM_FALLTHROUGH);

    /* X = IHL * 4 (the "load IP header length" MSH trick) */
    bpf_asm_stmt(a, BPF_LDX | BPF_B | BPF_MSH, ip_base);

    bpf_asm_check_two_ports(a, ip_base + CF_BPF_UDP_SRC_PORT_OFF, port1, port2, accept_label,
                            CF_BPF_ASM_FALLTHROUGH);
    bpf_asm_check_two_ports(a, ip_base + CF_BPF_UDP_DST_PORT_OFF, port1, port2, accept_label,
                            drop_label);
}

void bpf_asm_ipv6_udp_ports_branch(bpf_asm_t *a, __u32 ip_base, __u16 port1, __u16 port2,
                                    int accept_label, int drop_label)
{
    /* next-header (byte 6 of the fixed IPv6 header) */
    bpf_asm_stmt(a, BPF_LD | BPF_B | BPF_ABS, ip_base + 6);
    bpf_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, CF_BPF_ASM_FALLTHROUGH, drop_label);

    /* X = ip_base + 40 (fixed IPv6 header length), so IND loads below are
     * relative to the UDP header start without a per-byte MSH trick. */
    bpf_asm_stmt(a, BPF_LDX | BPF_IMM, ip_base + 40);

    bpf_asm_check_two_ports(a, CF_BPF_UDP_SRC_PORT_OFF, port1, port2, accept_label,
                            CF_BPF_ASM_FALLTHROUGH);
    bpf_asm_check_two_ports(a, CF_BPF_UDP_DST_PORT_OFF, port1, port2, accept_label, drop_label);
}
