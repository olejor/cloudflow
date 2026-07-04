#include "stats.h"

#include <stdint.h>

#include "cf_log.h"
#include "cf_stats.h"

/* Reads a cf_source_stats_t counter, honoring reset_on_report. */
static unsigned long read_counter(atomic_ulong *v, int reset)
{
    return reset ? CF_ATOMIC_READ_AND_ZERO(*v) : CF_ATOMIC_READ(*v);
}

void cf_stats_report(cf_source_stats_t *stats, cf_redis_stats_t *redis_stats,
                     const cf_queue_t *q_rx, const cf_queue_t *q_redis, int reset_on_report)
{
    /* One value buffer per key rendered into the single cf_log() call: the
     * pointers must all stay live until cf_log() returns, so each needs its
     * own buffer (cf_log_u64 renders into the buffer it is handed). */
    char b_recv[24], b_kdrop[24], b_rxqd[24], b_rxqdep[24], b_trunc[24];
    char b_efmt[24], b_efmt4[24], b_efmt6[24], b_skip[24], b_warn[24];
    char b_oversz[24], b_fqdep[24], b_fqdrop[24];
    char b_xadd[24], b_xerr[24], b_xlost[24], b_recon[24], b_xavg[24];
    char b_redisdepth_live[24];

    /* rx-reader / pcap-replay counters. */
    unsigned long packets_received = read_counter(&stats->rx.packets_received_total, reset_on_report);
    unsigned long packets_dropped = read_counter(&stats->rx.packets_dropped_total, reset_on_report);
    unsigned long rx_queue_drop = read_counter(&stats->rx.rx_queue_drop_total, reset_on_report);
    unsigned long packets_truncated = read_counter(&stats->rx.packets_truncated_total, reset_on_report);

    /* formatter counters. */
    unsigned long events_formatted = read_counter(&stats->events_formatted_total, reset_on_report);
    unsigned long events_formatted_v4 =
        read_counter(&stats->events_formatted_dhcpv4_total, reset_on_report);
    unsigned long events_formatted_v6 =
        read_counter(&stats->events_formatted_dhcpv6_total, reset_on_report);
    unsigned long packets_skipped = read_counter(&stats->packets_skipped_total, reset_on_report);
    unsigned long parse_warnings = read_counter(&stats->parse_warnings_total, reset_on_report);
    unsigned long events_oversize =
        read_counter(&stats->events_oversize_dropped_total, reset_on_report);
    unsigned long formatter_queue_drop =
        read_counter(&stats->formatter_queue_drop_total, reset_on_report);

    /* Gauges: always read live, never reset. The two queue depths are
     * re-sampled from the live queues so the line is current as of emission
     * (the per-thread sampled gauges in `stats` lag by up to one tick). */
    unsigned long rx_queue_depth = q_rx ? (unsigned long)cf_queue_length(q_rx)
                                        : CF_ATOMIC_READ(stats->rx.rx_queue_depth);
    unsigned long formatter_queue_depth = CF_ATOMIC_READ(stats->formatter_queue_depth);
    unsigned long redis_queue_depth = q_redis ? (unsigned long)cf_queue_length(q_redis) : 0;

    /* Redis producer counters -- always cumulative (the library owns them). */
    unsigned long xadd_total = CF_ATOMIC_READ(redis_stats->xadd_total);
    unsigned long xadd_errors = CF_ATOMIC_READ(redis_stats->xadd_errors_total);
    unsigned long xadd_latency_ns = CF_ATOMIC_READ(redis_stats->xadd_latency_ns_total);
    unsigned long reconnects = CF_ATOMIC_READ(redis_stats->redis_reconnects_total);
    unsigned long events_lost = CF_ATOMIC_READ(redis_stats->events_lost_total);
    unsigned long xadd_avg_latency_ns = xadd_total ? xadd_latency_ns / xadd_total : 0;

    cf_log(CF_LOG_INFO, "stats",
           "packets_received_total", cf_log_u64(b_recv, sizeof(b_recv), packets_received),
           "packets_dropped_total", cf_log_u64(b_kdrop, sizeof(b_kdrop), packets_dropped),
           "rx_queue_drop_total", cf_log_u64(b_rxqd, sizeof(b_rxqd), rx_queue_drop),
           "rx_queue_depth", cf_log_u64(b_rxqdep, sizeof(b_rxqdep), rx_queue_depth),
           "packets_truncated_total", cf_log_u64(b_trunc, sizeof(b_trunc), packets_truncated),
           "events_formatted_total", cf_log_u64(b_efmt, sizeof(b_efmt), events_formatted),
           "events_formatted_dhcpv4_total",
           cf_log_u64(b_efmt4, sizeof(b_efmt4), events_formatted_v4),
           "events_formatted_dhcpv6_total",
           cf_log_u64(b_efmt6, sizeof(b_efmt6), events_formatted_v6),
           "packets_skipped_total", cf_log_u64(b_skip, sizeof(b_skip), packets_skipped),
           "parse_warnings_total", cf_log_u64(b_warn, sizeof(b_warn), parse_warnings),
           "events_oversize_dropped_total", cf_log_u64(b_oversz, sizeof(b_oversz), events_oversize),
           "formatter_queue_depth", cf_log_u64(b_fqdep, sizeof(b_fqdep), formatter_queue_depth),
           "formatter_queue_drop_total",
           cf_log_u64(b_fqdrop, sizeof(b_fqdrop), formatter_queue_drop),
           "redis_queue_depth", cf_log_u64(b_redisdepth_live, sizeof(b_redisdepth_live),
                                           redis_queue_depth),
           "xadd_total", cf_log_u64(b_xadd, sizeof(b_xadd), xadd_total),
           "xadd_errors_total", cf_log_u64(b_xerr, sizeof(b_xerr), xadd_errors),
           "events_lost_total", cf_log_u64(b_xlost, sizeof(b_xlost), events_lost),
           "redis_reconnects_total", cf_log_u64(b_recon, sizeof(b_recon), reconnects),
           "xadd_avg_latency_ns", cf_log_u64(b_xavg, sizeof(b_xavg), xadd_avg_latency_ns),
           NULL);
}
