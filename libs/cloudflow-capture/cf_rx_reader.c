#define _GNU_SOURCE

#include "cf_rx_reader.h"

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
 * TPACKET_V3 ring capture: socket + block ring setup, block walk, epoll
 * loop. The walk follows the correct TPACKET_V3 block_walk (num_pkts +
 * tp_next_offset), not a per-frame walk.
 */

static int attach_filter(int fd, const struct sock_filter *bpf, unsigned short bpf_len)
{
    struct sock_fprog prog;

    if (!bpf || bpf_len == 0)
        return 0; /* no filter: capture every frame on the interface */

    memset(&prog, 0, sizeof(prog));
    prog.len = bpf_len;
    prog.filter = (struct sock_filter *)bpf;

    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0) {
        cf_log(CF_LOG_ERROR, "SO_ATTACH_FILTER failed", "error", strerror(errno), NULL);
        return -1;
    }

    return 0;
}

typedef struct {
    int fd;
    void *mem;
    size_t mem_size;
    uint32_t block_size;
    uint32_t block_count;
    struct iovec *iov;
} cf_rx_ring_t;

typedef struct {
    cf_rx_reader_config_t cfg;
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

static void handle_packet(const struct tpacket3_hdr *packet, const cf_rx_reader_config_t *cfg)
{
    cf_packet_item_t item;
    const uint8_t *frame;
    uint32_t captured;
    uint32_t copy_len;

    /* Initialize every header field explicitly rather than memset-ing the whole
     * ~2 KB struct on every packet: the tail of item.data past captured_len is
     * never read (consumers bound their reads by captured_len), so zeroing it
     * is pure waste in the RX hot path. */
    item.flags = 0;
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
        CF_ATOMIC_ADD(cfg->stats->rx_bytes_copied_total, (unsigned long)copy_len);
        if (item.flags & CF_PACKET_FLAG_TRUNCATED)
            CF_ATOMIC_INC(cfg->stats->packets_truncated_total);
    }

    (void)cf_queue_push_policy(cfg->out, &item, sizeof(item), cfg->on_full,
                                cfg->stats ? &cfg->stats->rx_queue_drop_total : NULL);
}

static void block_walk(const struct tpacket_block_desc *block, const cf_rx_reader_config_t *cfg)
{
    const struct tpacket3_hdr *packet;
    uint32_t i;

    packet = (const struct tpacket3_hdr *)((const uint8_t *)block + block->hdr.bh1.offset_to_first_pkt);

    for (i = 0; i < block->hdr.bh1.num_pkts; i++) {
        handle_packet(packet, cfg);
        packet = (const struct tpacket3_hdr *)((const uint8_t *)packet + packet->tp_next_offset);
    }
}

static void sample_kernel_stats(cf_rx_stats_t *stats, int fd, const cf_queue_t *out)
{
    struct tpacket_stats_v3 st;
    socklen_t len = sizeof(st);

    if (!stats)
        return;

    if (getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &st, &len) == 0)
        /* getsockopt(PACKET_STATISTICS) resets the kernel counters on every
         * read, so st.tp_drops is only the drops since the previous sample.
         * Accumulate the delta so packets_dropped_total is a true running
         * total (and the reporting thread's CF_ATOMIC_READ_AND_ZERO still
         * yields correct per-interval values). */
        CF_ATOMIC_ADD(stats->packets_dropped_total, st.tp_drops);
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

static int rx_ring_setup(const cf_rx_reader_config_t *cfg, cf_rx_ring_t *ring)
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

    if (attach_filter(ring->fd, cfg->bpf, cfg->bpf_len) != 0)
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
            /* Timeout tick: re-sample kernel drop stats and queue depth. */
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

int cf_rx_reader_start(const cf_rx_reader_config_t *cfg)
{
    if (!cfg || !cfg->out || !cfg->stats) {
        cf_log(CF_LOG_ERROR, "cf_rx_reader_start: invalid config (out/stats required)", NULL);
        return -1;
    }

    if (atomic_load(&g_rx_reader.started)) {
        cf_log(CF_LOG_ERROR, "cf_rx_reader_start: already started", NULL);
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

void cf_rx_reader_stop(void)
{
    if (!atomic_load(&g_rx_reader.started))
        return;

    cf_stop_notify(0);
    pthread_join(g_rx_reader.thread, NULL);

    rx_ring_teardown(&g_rx_reader.ring);

    atomic_store(&g_rx_reader.started, false);
}
