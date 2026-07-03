#ifndef CF_SOURCE_DHCP_RX_READER_H
#define CF_SOURCE_DHCP_RX_READER_H

/* WP-08: TPACKET_V3 mmap RX ring capture, lifted from
 * import/network_syslog_collector/src/rx-ring.c (socket setup, block ring
 * config, epoll wait loop, block_walk, TP_STATUS_KERNEL handback,
 * SCHED_FIFO attempt, PACKET_STATISTICS) per docs/design/03-source-dhcp.md.
 * Do NOT copy import/network_dhcp_collector/src/ring.c's per-frame walk --
 * it is wrong for TPACKET_V3.
 *
 * Per D10 (docs/design/00-overview.md), this module does no parsing: it
 * copies the raw frame plus ring timestamp into a cf_packet_item_t and
 * pushes it to `out`. All DHCP parsing happens later, in the
 * event-formatter thread (WP-10). */

#include <stdint.h>

#include "cf_queue.h"
#include "queue_policy.h"
#include "source_stats.h"

/* cf_packet_item_t.flags bits. Defined here rather than in cloudflow.h
 * (libs/cloudflow-core) because that header belongs to a different WP and
 * is off-limits to modify; the WP-08 spec explicitly calls for the flag
 * constants to live alongside rx_reader instead. */
#define CF_PACKET_FLAG_TRUNCATED 0x00000001u

/* Defaults applied by rx_reader_start() for any zero-valued field below,
 * per the WP-08 spec ("12 blocks x 4 MiB, 2048-byte frames"). All three
 * remain config-driven -- callers that want non-default sizing just set
 * the field. */
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
    cf_source_stats_t *stats;   /* required */
    cf_queue_full_policy_t on_full;
} rx_reader_config_t;

/* Spawns the capture thread. The socket/ring is opened synchronously by
 * this call (so an interface/permission error is reported immediately,
 * before the thread is spawned); the epoll loop then runs on its own
 * thread. Returns 0 on success, -1 on error (bad config, socket/ring setup
 * failure -- logged via cf_log). */
int rx_reader_start(const rx_reader_config_t *cfg);

/* Requests shutdown (if not already notified) and joins the capture
 * thread. Idempotent: safe to call when never started or already stopped. */
void rx_reader_stop(void);

#endif
