#ifndef CF_SOURCE_DHCP_SOURCE_STATS_H
#define CF_SOURCE_DHCP_SOURCE_STATS_H

/* cf_source_stats_t: the DHCP source's application counter/gauge struct (D8,
 * docs/architecture.md), shared by the whole cloudflow-source-dhcp pipeline.
 *
 * The generic rx-level counters (packets_received/dropped/truncated_total,
 * rx_queue_drop_total, rx_queue_depth) now live in libs/cloudflow-capture's
 * cf_rx_stats_t, embedded here as the `rx` member -- the shared rx-reader ring
 * loop (cf_rx_reader) and the pcap-replay reader (cf_pcap_replay) maintain
 * rx.* on their own; this struct adds the DHCP event-formatter's own counters
 * alongside it. WP-11 owns allocating/embedding this struct and emitting the
 * periodic stats log line.
 *
 * Every field is atomic_ulong so any thread can update its own fields with
 * the CF_ATOMIC_* macros (libs/cloudflow-core/cf_stats.h) without locking;
 * the stats-reporting thread reads them with CF_ATOMIC_READ /
 * CF_ATOMIC_READ_AND_ZERO depending on config's stats.reset_on_report.
 *
 * Metric names match AGENTS.md's "Useful CloudFlow service metrics" list
 * and the counters named explicitly in docs/dhcp-source.md's
 * WP-08/WP-10 sections. */

#include <stdatomic.h>

#include "cf_rx_stats.h"

typedef struct {
    /* --- rx-reader / pcap-replay (generic, libs/cloudflow-capture) -----
     * packets_received_total, packets_dropped_total, rx_queue_drop_total,
     * rx_queue_depth, packets_truncated_total. */
    cf_rx_stats_t rx;

    /* --- event-formatter (WP-10) ------------------------------------ */

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
