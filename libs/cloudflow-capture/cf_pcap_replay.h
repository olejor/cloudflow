#ifndef CF_CAPTURE_PCAP_REPLAY_H
#define CF_CAPTURE_PCAP_REPLAY_H

/* Classic-pcap offline reader. Feeds the same cf_packet_item_t / cf_queue_t
 * used by cf_rx_reader.h, so replay and live capture are interchangeable
 * inputs to the rest of a source pipeline (the DHCP source's --replay flag).
 * Moved from sources/cloudflow-source-dhcp/src/pcap_replay.{c,h} into
 * libs/cloudflow-capture so a second source can reuse it (synergy item A2);
 * its `stats` parameter is now a cf_rx_stats_t (it only ever touches
 * rx-level fields). */

#include "cf_queue.h"
#include "cf_queue_policy.h"
#include "cf_rx_stats.h"

/* Pushes every frame of a classic pcap file at `path` into `out`, using
 * each record's pcap timestamp as observed_time_unix_nano. Synchronous;
 * returns the number of frames read (queued or dropped) on success, -1 on
 * error (open failure, truncated/corrupt file, unsupported magic --
 * including pcapng's 0x0a0d0d0a, logged with a clear cf_log error -- or a
 * link-layer type other than DLT_EN10MB/1).
 *
 * The trailing `on_full` parameter selects D9's on_full policy for the
 * push into `out`; drops are counted in `stats->rx_queue_drop_total`, the
 * same counter cf_rx_reader uses for its q_pkt pushes -- replay and live
 * capture feed the same queue, so they share its drop accounting too.
 *
 * Accepts the standard classic-pcap magic in both byte orders
 * (0xa1b2c3d4 / 0xd4c3b2a1, microsecond timestamps) and the
 * nanosecond-timestamp variant in both byte orders (0xa1b23c4d /
 * 0x4d3cb2a1, the libpcap-defined nanosecond magic) plus 0xa3b4c3d4 (the
 * nanosecond-variant magic). `stats` may be NULL (counters simply are not
 * updated). */
long pcap_replay_file(const char *path, cf_queue_t *out, cf_rx_stats_t *stats,
                       cf_queue_full_policy_t on_full);

#endif
