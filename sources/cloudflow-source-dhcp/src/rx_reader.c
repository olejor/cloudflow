#define _GNU_SOURCE

#include "rx_reader.h"

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include "cf_log.h"
#include "cf_stats.h"
#include "cf_sync.h"
#include "cloudflow.h"

/* ------------------------------------------------------------------------
 * DHCP cBPF filter assembler
 *
 * Lifted-and-adapted from import/network_dhcp_collector/src/main.c's
 * attach_bpf(), per the WP-08 spec: VLAN-aware, matches UDP DHCP ports.
 * Two adaptations over the prototype:
 *
 *   1. The prototype matches dst port only; the spec calls for dst OR src
 *      port 67/68/546/547, so every port comparison here is duplicated for
 *      both the source and destination port position of the UDP header.
 *   2. The prototype's VLAN branch re-reads the (possibly-VLAN) EtherType
 *      correctly, but then falls through into the *same* fixed byte
 *      offsets used for the untagged case (e.g. IPv4 protocol always read
 *      from byte 23, i.e. Ethernet-header-plus-9, even when a 4-byte
 *      802.1Q tag pushed the real IPv4 header to byte 18). That means a
 *      VLAN-tagged frame is filtered using bytes that actually belong to
 *      the payload, not the IP header -- effectively random behavior for
 *      tagged traffic. This version keeps two full copies of the
 *      IPv4/IPv6 matching logic, one based at Ethernet+14 (untagged) and
 *      one based at Ethernet+18 (single 802.1Q tag), so every fixed offset
 *      is correct for the frame it actually applies to.
 *
 * Only a single VLAN tag is unwrapped (the spec's "single-tagged 802.1Q
 * frames"); QinQ/double-tagging is out of scope here.
 *
 * The program is assembled at runtime by a tiny two-pass "labels ->
 * relative offsets" assembler rather than hand-counted as a static array
 * of jt/jf byte offsets: this filter branches enough (VLAN x {v4,v6} x
 * {src,dst} x {67,68 or 546,547}) that hand-counted relative jumps are a
 * likely source of silent, hard-to-notice bugs (wrong-port packets
 * admitted, or right-port packets dropped) -- exactly the failure mode a
 * kernel-side filter must not have, since nothing upstream can no
 * longer see what the filter silently discarded. All jumps here are
 * forward-only (no loops), which is all the two-pass scheme supports, and
 * all this filter needs. */

typedef enum {
    BPF_LBL_VLAN,
    BPF_LBL_IP4_14,
    BPF_LBL_IP6_14,
    BPF_LBL_IP4_18,
    BPF_LBL_IP6_18,
    BPF_LBL_ACCEPT,
    BPF_LBL_DROP,
    BPF_LBL_COUNT,
} bpf_label_t;

#define BPF_ASM_MAX_INSNS 96
#define BPF_ASM_MAX_FIXUPS 96
#define BPF_ASM_FALLTHROUGH (-1) /* jt/jf target meaning "the next instruction" */

typedef struct {
    struct sock_filter insns[BPF_ASM_MAX_INSNS];
    int n;
    int label_pos[BPF_LBL_COUNT];

    int fixup_insn[BPF_ASM_MAX_FIXUPS];
    int fixup_is_jt[BPF_ASM_MAX_FIXUPS];
    bpf_label_t fixup_label[BPF_ASM_MAX_FIXUPS];
    int n_fixups;

    int error;
} bpf_asm_t;

static void bpf_asm_init(bpf_asm_t *a)
{
    int i;

    memset(a, 0, sizeof(*a));
    for (i = 0; i < BPF_LBL_COUNT; i++)
        a->label_pos[i] = -1;
}

static void bpf_asm_label(bpf_asm_t *a, bpf_label_t label)
{
    a->label_pos[label] = a->n;
}

/* Emits a non-branching instruction (BPF_STMT-shaped: k only, jt=jf=0). */
static void bpf_asm_stmt(bpf_asm_t *a, __u16 code, __u32 k)
{
    if (a->n >= BPF_ASM_MAX_INSNS) {
        a->error = 1;
        return;
    }

    a->insns[a->n].code = code;
    a->insns[a->n].jt = 0;
    a->insns[a->n].jf = 0;
    a->insns[a->n].k = k;
    a->n++;
}

/* Emits a branching instruction (BPF_JUMP-shaped). jt_label/jf_label are
 * either a bpf_label_t or BPF_ASM_FALLTHROUGH; either way the real jt/jf
 * byte offsets are resolved by bpf_asm_finish() once every label's
 * position is known. */
static void bpf_asm_jump(bpf_asm_t *a, __u16 code, __u32 k, int jt_label, int jf_label)
{
    int idx;

    if (a->n >= BPF_ASM_MAX_INSNS) {
        a->error = 1;
        return;
    }

    idx = a->n;
    a->insns[idx].code = code;
    a->insns[idx].jt = 0;
    a->insns[idx].jf = 0;
    a->insns[idx].k = k;
    a->n++;

    if (jt_label != BPF_ASM_FALLTHROUGH) {
        if (a->n_fixups >= BPF_ASM_MAX_FIXUPS) {
            a->error = 1;
            return;
        }
        a->fixup_insn[a->n_fixups] = idx;
        a->fixup_is_jt[a->n_fixups] = 1;
        a->fixup_label[a->n_fixups] = (bpf_label_t)jt_label;
        a->n_fixups++;
    }

    if (jf_label != BPF_ASM_FALLTHROUGH) {
        if (a->n_fixups >= BPF_ASM_MAX_FIXUPS) {
            a->error = 1;
            return;
        }
        a->fixup_insn[a->n_fixups] = idx;
        a->fixup_is_jt[a->n_fixups] = 0;
        a->fixup_label[a->n_fixups] = (bpf_label_t)jf_label;
        a->n_fixups++;
    }
}

/* Resolves every fixup into a concrete relative jt/jf offset. Returns 0 on
 * success, -1 if any label was never placed, a jump target ended up behind
 * its jump (this assembler only supports forward jumps), the offset does
 * not fit cBPF's 8-bit jt/jf field, or the assembler ran out of scratch
 * space while building the program. */
static int bpf_asm_finish(bpf_asm_t *a)
{
    int i;

    if (a->error)
        return -1;

    for (i = 0; i < a->n_fixups; i++) {
        int insn_idx = a->fixup_insn[i];
        int target = a->label_pos[a->fixup_label[i]];
        int delta;

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

/* UDP header byte offsets, relative to the start of the UDP header:
 * source port at +0, destination port at +2. */
#define UDP_SRC_PORT_OFF 0
#define UDP_DST_PORT_OFF 2

/* Emits: "if A == port1 goto ACCEPT; if A == port2 goto ACCEPT; else goto
 * final_jf_label;". Used once per {src,dst} port position to check both
 * DHCP ports for the address family in play. `final_jf_label` is
 * BPF_ASM_FALLTHROUGH when the caller has another check to fall into (e.g.
 * src-port check falling into the dst-port check), or BPF_LBL_DROP for the
 * last check in a branch -- note this only ever needs a jt/jf-encoded
 * jump (never BPF_JMP|BPF_JA, whose target lives in `k`, not jt/jf, and so
 * cannot be resolved by this assembler's label-fixup mechanism). */
static void bpf_asm_check_two_ports(bpf_asm_t *a, __u32 ind_k, __u16 port1, __u16 port2,
                                     int final_jf_label)
{
    bpf_asm_stmt(a, BPF_LD | BPF_H | BPF_IND, ind_k);
    bpf_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, port1, BPF_LBL_ACCEPT, BPF_ASM_FALLTHROUGH);
    bpf_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, port2, BPF_LBL_ACCEPT, final_jf_label);
}

/* Emits the IPv4 branch (proto/frag/port checks) assuming the IPv4 header
 * starts at Ethernet offset `ip_base` (14 untagged, 18 single-VLAN-tagged).
 * Falls through to DROP on any mismatch. */
static void bpf_asm_ipv4_branch(bpf_asm_t *a, __u32 ip_base)
{
    /* ip.protocol (byte 9 of the IP header) */
    bpf_asm_stmt(a, BPF_LD | BPF_B | BPF_ABS, ip_base + 9);
    bpf_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, BPF_ASM_FALLTHROUGH, BPF_LBL_DROP);

    /* flags+fragment-offset (bytes 6-7): reject non-first fragments, same
     * "ip[6:2] & 0x1fff != 0" idiom tcpdump/the lifted prototype use. */
    bpf_asm_stmt(a, BPF_LD | BPF_H | BPF_ABS, ip_base + 6);
    bpf_asm_jump(a, BPF_JMP | BPF_JSET | BPF_K, 0x1fffu, BPF_LBL_DROP, BPF_ASM_FALLTHROUGH);

    /* X = IHL * 4 (the "load IP header length" MSH trick) */
    bpf_asm_stmt(a, BPF_LDX | BPF_B | BPF_MSH, ip_base);

    bpf_asm_check_two_ports(a, ip_base + UDP_SRC_PORT_OFF, 67, 68, BPF_ASM_FALLTHROUGH);
    bpf_asm_check_two_ports(a, ip_base + UDP_DST_PORT_OFF, 67, 68, BPF_LBL_DROP);
}

/* Emits the IPv6 branch, base at Ethernet offset `ip_base`. Ignores IPv6
 * extension headers (fixed 40-byte header assumed), matching the lifted
 * prototype's simplification. Falls through to DROP on any mismatch. */
static void bpf_asm_ipv6_branch(bpf_asm_t *a, __u32 ip_base)
{
    /* next-header (byte 6 of the fixed IPv6 header) */
    bpf_asm_stmt(a, BPF_LD | BPF_B | BPF_ABS, ip_base + 6);
    bpf_asm_jump(a, BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, BPF_ASM_FALLTHROUGH, BPF_LBL_DROP);

    /* X = ip_base + 40 (fixed IPv6 header length), so IND loads below are
     * relative to the UDP header start without a per-byte MSH trick. */
    bpf_asm_stmt(a, BPF_LDX | BPF_IMM, ip_base + 40);

    bpf_asm_check_two_ports(a, UDP_SRC_PORT_OFF, 546, 547, BPF_ASM_FALLTHROUGH);
    bpf_asm_check_two_ports(a, UDP_DST_PORT_OFF, 546, 547, BPF_LBL_DROP);
}

/* Builds the full VLAN-aware DHCP filter into `out` (capacity `max`
 * instructions). Returns the instruction count on success, -1 on assembler
 * failure (should only happen if this function itself has a bug -- there
 * is no runtime-variable input to this program). */
static int build_dhcp_bpf_filter(struct sock_filter *out, int max)
{
    bpf_asm_t a;

    bpf_asm_init(&a);

    /* EtherType at offset 12, assuming no VLAN tag. */
    bpf_asm_stmt(&a, BPF_LD | BPF_H | BPF_ABS, 12);
    bpf_asm_jump(&a, BPF_JMP | BPF_JEQ | BPF_K, ETH_P_8021Q, BPF_LBL_VLAN, BPF_ASM_FALLTHROUGH);
    bpf_asm_jump(&a, BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IP, BPF_LBL_IP4_14, BPF_ASM_FALLTHROUGH);
    bpf_asm_jump(&a, BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IPV6, BPF_LBL_IP6_14, BPF_LBL_DROP);

    bpf_asm_label(&a, BPF_LBL_VLAN);
    bpf_asm_stmt(&a, BPF_LD | BPF_H | BPF_ABS, 16); /* real EtherType past the VLAN tag */
    bpf_asm_jump(&a, BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IP, BPF_LBL_IP4_18, BPF_ASM_FALLTHROUGH);
    bpf_asm_jump(&a, BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IPV6, BPF_LBL_IP6_18, BPF_LBL_DROP);

    bpf_asm_label(&a, BPF_LBL_IP4_14);
    bpf_asm_ipv4_branch(&a, 14);

    bpf_asm_label(&a, BPF_LBL_IP6_14);
    bpf_asm_ipv6_branch(&a, 14);

    bpf_asm_label(&a, BPF_LBL_IP4_18);
    bpf_asm_ipv4_branch(&a, 18);

    bpf_asm_label(&a, BPF_LBL_IP6_18);
    bpf_asm_ipv6_branch(&a, 18);

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

static int attach_dhcp_bpf(int fd)
{
    struct sock_filter filter[BPF_ASM_MAX_INSNS];
    struct sock_fprog prog;
    int n;

    n = build_dhcp_bpf_filter(filter, BPF_ASM_MAX_INSNS);
    if (n < 0) {
        cf_log(CF_LOG_ERROR, "failed to assemble DHCP BPF filter", NULL);
        return -1;
    }

    memset(&prog, 0, sizeof(prog));
    prog.len = (unsigned short)n;
    prog.filter = filter;

    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0) {
        cf_log(CF_LOG_ERROR, "SO_ATTACH_FILTER failed", "error", strerror(errno), NULL);
        return -1;
    }

    return 0;
}

/* ------------------------------------------------------------------------
 * TPACKET_V3 ring capture: socket + block ring setup, block walk, epoll
 * loop. Structure lifted from import/network_syslog_collector/src/rx-ring.c
 * (read-only reference); the walk itself follows that file's block_walk(),
 * not import/network_dhcp_collector/src/ring.c's incorrect per-frame walk.
 */

typedef struct {
    int fd;
    void *mem;
    size_t mem_size;
    uint32_t block_size;
    uint32_t block_count;
    struct iovec *iov;
} cf_rx_ring_t;

typedef struct {
    rx_reader_config_t cfg;
    cf_rx_ring_t ring;
    pthread_t thread;
    atomic_bool started;
} cf_rx_reader_state_t;

static cf_rx_reader_state_t g_rx_reader;

static inline int block_is_ready(const struct tpacket_block_desc *block)
{
    return (block->hdr.bh1.block_status & TP_STATUS_USER) != 0;
}

static inline void block_mark_done(struct tpacket_block_desc *block)
{
    block->hdr.bh1.block_status = TP_STATUS_KERNEL;
}

static void handle_packet(const struct tpacket3_hdr *packet, const rx_reader_config_t *cfg)
{
    cf_packet_item_t item;
    const uint8_t *frame;
    uint32_t captured;
    uint32_t copy_len;

    memset(&item, 0, sizeof(item));

    item.observed_time_unix_nano =
        (int64_t)packet->tp_sec * 1000000000LL + (int64_t)packet->tp_nsec;
    item.packet_len = packet->tp_len;

    captured = packet->tp_snaplen;
    copy_len = captured;
    if (copy_len > CLOUDFLOW_PACKET_MAX_SIZE) {
        copy_len = CLOUDFLOW_PACKET_MAX_SIZE;
        item.flags |= CF_PACKET_FLAG_TRUNCATED;
    }
    item.captured_len = copy_len;

    frame = (const uint8_t *)packet + packet->tp_mac;
    memcpy(item.data, frame, copy_len);

    if (cfg->stats) {
        CF_ATOMIC_INC(cfg->stats->packets_received_total);
        if (item.flags & CF_PACKET_FLAG_TRUNCATED)
            CF_ATOMIC_INC(cfg->stats->packets_truncated_total);
    }

    (void)cf_queue_push_policy(cfg->out, &item, sizeof(item), cfg->on_full,
                                cfg->stats ? &cfg->stats->rx_queue_drop_total : NULL);
}

static void block_walk(const struct tpacket_block_desc *block, const rx_reader_config_t *cfg)
{
    const struct tpacket3_hdr *packet;
    uint32_t i;

    packet = (const struct tpacket3_hdr *)((const uint8_t *)block + block->hdr.bh1.offset_to_first_pkt);

    for (i = 0; i < block->hdr.bh1.num_pkts; i++) {
        handle_packet(packet, cfg);
        packet = (const struct tpacket3_hdr *)((const uint8_t *)packet + packet->tp_next_offset);
    }
}

static void sample_kernel_stats(cf_source_stats_t *stats, int fd, const cf_queue_t *out)
{
    struct tpacket_stats_v3 st;
    socklen_t len = sizeof(st);

    if (!stats)
        return;

    if (getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &st, &len) == 0)
        CF_ATOMIC_STORE(stats->packets_dropped_total, st.tp_drops);
    else
        cf_log(CF_LOG_WARN, "getsockopt(PACKET_STATISTICS) failed", "error", strerror(errno), NULL);

    CF_ATOMIC_STORE(stats->rx_queue_depth, cf_queue_length(out));
}

static int bind_fd_to_iface(int fd, const char *iface)
{
    struct ifreq ifr;
    struct sockaddr_ll sa;

    if (!iface || iface[0] == '\0')
        return 0; /* all interfaces, matches socket()'s ETH_P_ALL binding */

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface);

    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        cf_log(CF_LOG_ERROR, "SIOCGIFINDEX failed", "interface", iface, "error", strerror(errno), NULL);
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex = ifr.ifr_ifindex;

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        cf_log(CF_LOG_ERROR, "bind() failed", "interface", iface, "error", strerror(errno), NULL);
        return -1;
    }

    return 0;
}

static void rx_ring_teardown(cf_rx_ring_t *ring)
{
    if (ring->mem && ring->mem != MAP_FAILED)
        munmap(ring->mem, ring->mem_size);
    if (ring->fd >= 0)
        close(ring->fd);
    free(ring->iov);
    memset(ring, 0, sizeof(*ring));
    ring->fd = -1;
}

static int rx_ring_setup(const rx_reader_config_t *cfg, cf_rx_ring_t *ring)
{
    struct tpacket_req3 req;
    int pv = TPACKET_V3;
    uint32_t i;

    memset(ring, 0, sizeof(*ring));
    ring->fd = -1;

    ring->block_size = cfg->block_size ? cfg->block_size : RX_READER_DEFAULT_BLOCK_SIZE;
    ring->block_count = cfg->block_count ? cfg->block_count : RX_READER_DEFAULT_BLOCK_COUNT;

    ring->fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (ring->fd < 0) {
        cf_log(CF_LOG_ERROR, "socket(PF_PACKET) failed", "error", strerror(errno), NULL);
        return -1;
    }

    if (bind_fd_to_iface(ring->fd, cfg->interface_name) != 0)
        goto err;

    if (attach_dhcp_bpf(ring->fd) != 0)
        goto err;

    if (setsockopt(ring->fd, SOL_PACKET, PACKET_VERSION, &pv, sizeof(pv)) < 0) {
        cf_log(CF_LOG_ERROR, "setsockopt(PACKET_VERSION) failed", "error", strerror(errno), NULL);
        goto err;
    }

    memset(&req, 0, sizeof(req));
    req.tp_block_size = ring->block_size;
    req.tp_block_nr = ring->block_count;
    req.tp_frame_size = cfg->frame_size ? cfg->frame_size : RX_READER_DEFAULT_FRAME_SIZE;
    req.tp_frame_nr = (ring->block_size / req.tp_frame_size) * ring->block_count;

    if (setsockopt(ring->fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0) {
        cf_log(CF_LOG_ERROR, "setsockopt(PACKET_RX_RING) failed", "error", strerror(errno), NULL);
        goto err;
    }

    ring->mem_size = (size_t)ring->block_size * ring->block_count;
    ring->mem = mmap(NULL, ring->mem_size, PROT_READ | PROT_WRITE, MAP_SHARED, ring->fd, 0);
    if (ring->mem == MAP_FAILED) {
        cf_log(CF_LOG_ERROR, "mmap() of RX ring failed", "error", strerror(errno), NULL);
        goto err;
    }

    ring->iov = calloc(ring->block_count, sizeof(*ring->iov));
    if (!ring->iov) {
        cf_log(CF_LOG_ERROR, "failed to allocate ring iovec array", NULL);
        goto err;
    }

    for (i = 0; i < ring->block_count; i++) {
        ring->iov[i].iov_base = (uint8_t *)ring->mem + ((size_t)i * ring->block_size);
        ring->iov[i].iov_len = ring->block_size;
    }

    return 0;

err:
    rx_ring_teardown(ring);
    return -1;
}

static void try_sched_fifo(void)
{
    struct sched_param sp;

    memset(&sp, 0, sizeof(sp));
    sp.sched_priority = 32;

    if (sched_setscheduler(0, SCHED_FIFO, &sp) != 0) {
        cf_log(CF_LOG_WARN, "SCHED_FIFO unavailable, continuing at default priority",
               "error", strerror(errno), NULL);
    }
}

static void rx_reader_loop(cf_rx_reader_state_t *state)
{
    int epfd;
    struct epoll_event ev;
    struct epoll_event events[1];

    epfd = epoll_create1(0);
    if (epfd < 0) {
        cf_log(CF_LOG_ERROR, "epoll_create1() failed", "error", strerror(errno), NULL);
        return;
    }

    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.fd = state->ring.fd;

    if (epoll_ctl(epfd, EPOLL_CTL_ADD, state->ring.fd, &ev) != 0) {
        cf_log(CF_LOG_ERROR, "epoll_ctl() failed", "error", strerror(errno), NULL);
        close(epfd);
        return;
    }

    while (!cf_stop_notified()) {
        int nfds;
        uint32_t i;

        nfds = epoll_wait(epfd, events, 1, RX_READER_EPOLL_TIMEOUT_MS);
        if (nfds < 0) {
            if (errno == EINTR)
                continue;
            cf_log(CF_LOG_ERROR, "epoll_wait() failed", "error", strerror(errno), NULL);
            break;
        }

        if (nfds == 0) {
            /* Timeout tick: re-sample kernel drop stats and queue depth,
             * per the WP-08 spec. */
            sample_kernel_stats(state->cfg.stats, state->ring.fd, state->cfg.out);
            continue;
        }

        if (events[0].data.fd != state->ring.fd)
            continue;

        for (i = 0; i < state->ring.block_count; i++) {
            struct tpacket_block_desc *block = state->ring.iov[i].iov_base;

            if (!block_is_ready(block))
                continue;

            block_walk(block, &state->cfg);
            block_mark_done(block);
        }
    }

    close(epfd);
}

static void *rx_reader_thread_main(void *arg)
{
    cf_rx_reader_state_t *state = arg;

    pthread_setname_np(pthread_self(), "cf-rx-reader");

    try_sched_fifo();

    cf_log(CF_LOG_INFO, "rx-reader started",
           "interface", state->cfg.interface_name ? state->cfg.interface_name : "*", NULL);

    rx_reader_loop(state);

    cf_log(CF_LOG_INFO, "rx-reader stopped", NULL);

    return NULL;
}

int rx_reader_start(const rx_reader_config_t *cfg)
{
    if (!cfg || !cfg->out || !cfg->stats) {
        cf_log(CF_LOG_ERROR, "rx_reader_start: invalid config (out/stats required)", NULL);
        return -1;
    }

    if (atomic_load(&g_rx_reader.started)) {
        cf_log(CF_LOG_ERROR, "rx_reader_start: already started", NULL);
        return -1;
    }

    memset(&g_rx_reader, 0, sizeof(g_rx_reader));
    g_rx_reader.cfg = *cfg;

    if (rx_ring_setup(&g_rx_reader.cfg, &g_rx_reader.ring) != 0)
        return -1;

    if (pthread_create(&g_rx_reader.thread, NULL, rx_reader_thread_main, &g_rx_reader) != 0) {
        cf_log(CF_LOG_ERROR, "pthread_create() failed", "error", strerror(errno), NULL);
        rx_ring_teardown(&g_rx_reader.ring);
        return -1;
    }

    atomic_store(&g_rx_reader.started, true);

    return 0;
}

void rx_reader_stop(void)
{
    if (!atomic_load(&g_rx_reader.started))
        return;

    cf_stop_notify(0);
    pthread_join(g_rx_reader.thread, NULL);

    rx_ring_teardown(&g_rx_reader.ring);

    atomic_store(&g_rx_reader.started, false);
}
