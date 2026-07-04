#ifndef CF_CAPTURE_RX_READER_H
#define CF_CAPTURE_RX_READER_H

/* TPACKET_V3 mmap RX ring capture: socket setup, block ring config, epoll
 * wait loop, block walk, TP_STATUS_KERNEL handback, SCHED_FIFO attempt,
 * PACKET_STATISTICS sampling. Moved from
 * sources/cloudflow-source-dhcp/src/rx_reader.{c,h} into libs/cloudflow-capture
 * (synergy item A2) and made protocol-agnostic: the caller supplies a
 * pre-assembled cBPF program (build it with cf_bpf.h's assembler) which
 * cf_rx_reader_start() attaches via SO_ATTACH_FILTER. No parsing happens here:
 * each raw frame plus its ring timestamp is copied into a cf_packet_item_t and
 * pushed to `out`; all protocol parsing happens later, in the source's
 * event-formatter thread. */

#include <stdint.h>

#include <linux/filter.h> /* struct sock_filter */

#include "cf_queue.h"
#include "cf_queue_policy.h"
#include "cf_rx_stats.h"

/* Defaults applied by cf_rx_reader_start() for any zero-valued field below
 * ("12 blocks x 4 MiB, 2048-byte frames"). All three remain config-driven --
 * callers that want non-default sizing just set the field. */
#define RX_READER_DEFAULT_BLOCK_SIZE  (4u * 1024u * 1024u)
#define RX_READER_DEFAULT_BLOCK_COUNT 12u
#define RX_READER_DEFAULT_FRAME_SIZE  2048u

/* epoll_wait() timeout, in milliseconds. Bounds how promptly the capture
 * thread notices cf_stop_notified() and how often kernel PACKET_STATISTICS
 * are re-sampled into `stats`. */
#define RX_READER_EPOLL_TIMEOUT_MS 1000

typedef struct {
    const char *interface_name; /* NULL or "" = all interfaces */
    uint32_t block_size;        /* 0 = RX_READER_DEFAULT_BLOCK_SIZE */
    uint32_t block_count;       /* 0 = RX_READER_DEFAULT_BLOCK_COUNT */
    uint32_t frame_size;        /* 0 = RX_READER_DEFAULT_FRAME_SIZE */
    cf_queue_t *out;            /* of cf_packet_item_t; required */
    cf_rx_stats_t *stats;       /* required */
    cf_queue_full_policy_t on_full;

    /* Pre-assembled cBPF program attached via SO_ATTACH_FILTER before the
     * ring is set up. When `bpf` is NULL or `bpf_len` is 0, no filter is
     * attached and every frame on the interface is captured. */
    const struct sock_filter *bpf;
    unsigned short bpf_len;
} cf_rx_reader_config_t;

/* Spawns the capture thread. The socket/ring is opened synchronously by
 * this call (so an interface/permission error is reported immediately,
 * before the thread is spawned); the epoll loop then runs on its own
 * thread. Returns 0 on success, -1 on error (bad config, socket/ring setup
 * failure -- logged via cf_log). */
int cf_rx_reader_start(const cf_rx_reader_config_t *cfg);

/* Requests shutdown (if not already notified) and joins the capture
 * thread. Idempotent: safe to call when never started or already stopped. */
void cf_rx_reader_stop(void);

#endif
