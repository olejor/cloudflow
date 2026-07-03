#ifndef CF_SOURCE_DHCP_PCAP_REPLAY_H
#define CF_SOURCE_DHCP_PCAP_REPLAY_H

/* WP-08: classic-pcap offline reader, lifted-and-adapted from
 * import/network_dhcp_collector/src/replay.c (cap_run_pcap) per
 * docs/design/03-source-dhcp.md. Feeds the same cf_packet_item_t /
 * cf_queue_t used by rx_reader.h, so replay and live capture are
 * interchangeable inputs to the rest of the pipeline (WP-11's --replay
 * flag). */

#include "cf_queue.h"
#include "queue_policy.h"
#include "source_stats.h"

/* Pushes every frame of a classic pcap file at `path` into `out`, using
 * each record's pcap timestamp as observed_time_unix_nano. Synchronous;
 * returns the number of frames read (queued or dropped) on success, -1 on
 * error (open failure, truncated/corrupt file, unsupported magic --
 * including pcapng's 0x0a0d0d0a, logged with a clear cf_log error -- or a
 * link-layer type other than DLT_EN10MB/1).
 *
 * Deviation from the WP-08 spec's 3-argument signature
 * `pcap_replay_file(path, out, stats)`: that signature has no way to
 * express D9's on_full policy, which the same spec section requires
 * ("apply the same on_full policy queue machinery" as rx_reader). Rather
 * than hardcode a policy, this adds a trailing `on_full` parameter. Drops
 * are counted in `stats->rx_queue_drop_total`, the same counter rx_reader
 * uses for its q_pkt pushes -- replay and live capture feed the same
 * queue, so they share its drop accounting too. A 3-argument call site can
 * be reproduced exactly with `on_full = CF_ONFULL_DROP_NEWEST`.
 *
 * Accepts the standard classic-pcap magic in both byte orders
 * (0xa1b2c3d4 / 0xd4c3b2a1, microsecond timestamps) and the
 * nanosecond-timestamp variant in both byte orders (0xa1b23c4d /
 * 0x4d3cb2a1, the libpcap-defined nanosecond magic) plus 0xa3b4c3d4 (the
 * nanosecond-variant magic named explicitly in the WP-08 task
 * description). `stats` may be NULL (counters simply are not updated). */
long pcap_replay_file(const char *path, cf_queue_t *out, cf_source_stats_t *stats,
                       cf_queue_full_policy_t on_full);

#endif
