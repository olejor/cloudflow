#ifndef CF_SOURCE_DHCP_SOURCE_STATS_H
#define CF_SOURCE_DHCP_SOURCE_STATS_H

/* cf_source_stats_t: the atomic counter/gauge struct shared by the whole
 * cloudflow-source-dhcp pipeline (D8, docs/design/00-overview.md). WP-11
 * owns allocating/embedding this struct and emitting the periodic
 * structured stats log line from it; WP-08 (this WP) and WP-10 each only
 * touch their own fields. It is defined here, under WP-08, because
 * rx_reader.h/pcap_replay.h need the type -- WP-11's src/stats.h is
 * expected to just `#include` this header rather than redefine the type
 * (see sources/cloudflow-source-dhcp/README.md).
 *
 * Every field is atomic_ulong so any thread can update its own fields with
 * the CF_ATOMIC_* macros (libs/cloudflow-core/cf_stats.h) without locking;
 * the stats-reporting thread reads them with CF_ATOMIC_READ /
 * CF_ATOMIC_READ_AND_ZERO depending on config's stats.reset_on_report.
 *
 * Metric names match AGENTS.md's "Useful CloudFlow service metrics" list
 * and the counters named explicitly in docs/design/03-source-dhcp.md's
 * WP-08/WP-10 sections. */

#include <stdatomic.h>

typedef struct {
    /* --- rx-reader / pcap-replay (WP-08) ---------------------------- */

    /* Every frame observed (ring capture) or read (pcap replay), whether
     * or not it was successfully queued. */
    atomic_ulong packets_received_total;

    /* Kernel-side drops, sampled from getsockopt(PACKET_STATISTICS) each
     * epoll timeout tick. Always 0 for pcap replay (no kernel ring). */
    atomic_ulong packets_dropped_total;

    /* Our own on_full drops pushing into the rx -> formatter queue
     * (q_pkt), per D9. */
    atomic_ulong rx_queue_drop_total;

    /* Gauge: q_pkt depth, sampled at the same time as packets_dropped_total. */
    atomic_ulong rx_queue_depth;

    /* Frames whose captured bytes exceeded CLOUDFLOW_PACKET_MAX_SIZE and
     * were copied truncated (CF_PACKET_FLAG_TRUNCATED set). */
    atomic_ulong packets_truncated_total;

    /* --- event-formatter (WP-10) ------------------------------------
     * Defined here now, per the WP-08 task, so this struct is already
     * complete when WP-10 lands -- rx-reader/pcap-replay never touch these
     * fields. */

    /* Total events successfully built and pushed to q_evt, across both
     * protocols; the two fields below are the per-protocol breakdown. */
    atomic_ulong events_formatted_total;
    atomic_ulong events_formatted_dhcpv4_total;
    atomic_ulong events_formatted_dhcpv6_total;

    /* Packets that decap/classification could not attribute to DHCPv4 or
     * DHCPv6 (BPF slippage, replay of non-DHCP captures, etc). */
    atomic_ulong packets_skipped_total;

    /* Non-fatal parser warnings (malformed-but-recoverable options, etc). */
    atomic_ulong parse_warnings_total;

    /* D11: events that still exceeded CLOUDFLOW_EVENT_MAX_SIZE even after
     * dropping raw_dhcp_payload, and were dropped rather than sent. */
    atomic_ulong events_oversize_dropped_total;

    /* Gauge: q_evt depth, sampled at stats time. */
    atomic_ulong formatter_queue_depth;

    /* Our own on_full drops pushing into the formatter -> redis-producer
     * queue (q_evt), per D9. */
    atomic_ulong formatter_queue_drop_total;
} cf_source_stats_t;

#endif
