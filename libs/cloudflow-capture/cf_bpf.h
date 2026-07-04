#ifndef CF_CAPTURE_BPF_H
#define CF_CAPTURE_BPF_H

/* Generic two-pass cBPF assembler + reusable UDP/VLAN-offset filter
 * primitives, moved out of sources/cloudflow-source-dhcp/src/rx_reader.c into
 * libs/cloudflow-capture (synergy item A2) so every capture-based source
 * builds its SO_ATTACH_FILTER program on ONE shared, tested implementation of
 * this delicate, bug-prone machinery -- a real VLAN-offset bug was found here
 * once, and a kernel-side filter must have exactly one home. A source's own
 * DHCP/DNS-specific filter leaf lays out the ethertype/VLAN dispatch and picks
 * the ports, then calls the branch primitives below.
 *
 * The program is assembled by a tiny "labels -> relative offsets" pass rather
 * than hand-counted jt/jf byte offsets: a UDP-port filter branches enough
 * (VLAN x {v4,v6} x {src,dst} x port-pair) that hand-counted relative jumps
 * are a likely source of silent, hard-to-notice bugs (wrong-port packets
 * admitted, or right-port packets dropped) -- exactly the failure mode a
 * kernel-side filter must not have. All jumps are forward-only (no loops),
 * which is all the two-pass scheme supports. */

#include <linux/filter.h>

#define CF_BPF_ASM_MAX_INSNS 96
#define CF_BPF_ASM_MAX_FIXUPS 96
#define CF_BPF_ASM_MAX_LABELS 32
#define CF_BPF_ASM_FALLTHROUGH (-1) /* jt/jf target meaning "the next instruction" */

typedef struct {
    struct sock_filter insns[CF_BPF_ASM_MAX_INSNS];
    int n;
    int label_pos[CF_BPF_ASM_MAX_LABELS];

    int fixup_insn[CF_BPF_ASM_MAX_FIXUPS];
    int fixup_is_jt[CF_BPF_ASM_MAX_FIXUPS];
    int fixup_label[CF_BPF_ASM_MAX_FIXUPS];
    int n_fixups;

    int error;
} bpf_asm_t;

/* Labels are small non-negative ints in [0, CF_BPF_ASM_MAX_LABELS); a leaf
 * defines its own enum of label ids and passes them here. */

void bpf_asm_init(bpf_asm_t *a);

/* Marks the current position as `label` (a later jump can resolve to it). */
void bpf_asm_label(bpf_asm_t *a, int label);

/* Emits a non-branching instruction (BPF_STMT-shaped: k only, jt=jf=0). */
void bpf_asm_stmt(bpf_asm_t *a, __u16 code, __u32 k);

/* Emits a branching instruction (BPF_JUMP-shaped). jt_label/jf_label are
 * either a label id or CF_BPF_ASM_FALLTHROUGH; either way the real jt/jf
 * byte offsets are resolved by bpf_asm_finish() once every label's position
 * is known. */
void bpf_asm_jump(bpf_asm_t *a, __u16 code, __u32 k, int jt_label, int jf_label);

/* Resolves every fixup into a concrete relative jt/jf offset. Returns 0 on
 * success, -1 if any label was never placed, a jump target ended up behind
 * its jump (forward jumps only), the offset does not fit cBPF's 8-bit jt/jf
 * field, or the assembler ran out of scratch space while building. */
int bpf_asm_finish(bpf_asm_t *a);

/* UDP header byte offsets, relative to the start of the UDP header:
 * source port at +0, destination port at +2. */
#define CF_BPF_UDP_SRC_PORT_OFF 0
#define CF_BPF_UDP_DST_PORT_OFF 2

/* Emits: "if A == port1 goto accept_label; if A == port2 goto accept_label;
 * else goto final_jf_label;". Used once per {src,dst} port position.
 * `final_jf_label` is CF_BPF_ASM_FALLTHROUGH when the caller has another
 * check to fall into (e.g. src-port check falling into the dst-port check),
 * or the drop label for the last check in a branch. */
void bpf_asm_check_two_ports(bpf_asm_t *a, __u32 ind_k, __u16 port1, __u16 port2,
                             int accept_label, int final_jf_label);

/* Emits the IPv4 UDP branch (proto/frag/two-port checks) assuming the IPv4
 * header starts at Ethernet offset `ip_base` (14 untagged, 18
 * single-VLAN-tagged). Matches src OR dst UDP port against port1/port2,
 * jumping to `accept_label` on a match and falling through to `drop_label`
 * on any mismatch. */
void bpf_asm_ipv4_udp_ports_branch(bpf_asm_t *a, __u32 ip_base, __u16 port1, __u16 port2,
                                    int accept_label, int drop_label);

/* Emits the IPv6 UDP branch, base at Ethernet offset `ip_base`. Ignores IPv6
 * extension headers (fixed 40-byte header assumed). Otherwise as
 * bpf_asm_ipv4_udp_ports_branch. */
void bpf_asm_ipv6_udp_ports_branch(bpf_asm_t *a, __u32 ip_base, __u16 port1, __u16 port2,
                                    int accept_label, int drop_label);

/* TCP header byte offsets, relative to the start of the TCP header: source
 * port at +0, destination port at +2 (identical layout to the UDP header). */
#define CF_BPF_TCP_SRC_PORT_OFF 0
#define CF_BPF_TCP_DST_PORT_OFF 2

/* TCP counterparts of the UDP branch primitives above. Same shape (IP protocol
 * check + non-first-fragment reject + src/dst two-port check), but match IP
 * protocol == TCP (6) and read the ports from the TCP header.
 *
 * KEY DIFFERENCE from the UDP branches: on a protocol/port MISMATCH (or a
 * non-first fragment) these jump to `mismatch_label` rather than an implied
 * drop. That lets a caller CHAIN transports for one IP version -- point the
 * UDP branch's mismatch label at the TCP branch, and the TCP branch's mismatch
 * label at the final drop, giving "try UDP:port, else try TCP:port, else drop"
 * (the DNS udp/53 + tcp/53 filter). Passing the drop label as `mismatch_label`
 * degenerates to the same "match or drop" behaviour as the UDP branches.
 *
 * The existing UDP branch functions already take their mismatch target as the
 * final label argument (named `drop_label`), so no UDP variant is needed to
 * chain into a TCP branch: pass the TCP branch's label as that argument. */
void bpf_asm_ipv4_tcp_ports_branch(bpf_asm_t *a, __u32 ip_base, __u16 port1, __u16 port2,
                                    int accept_label, int mismatch_label);
void bpf_asm_ipv6_tcp_ports_branch(bpf_asm_t *a, __u32 ip_base, __u16 port1, __u16 port2,
                                    int accept_label, int mismatch_label);

#endif
