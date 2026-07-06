#include "stats.h"

#include <stdint.h>

#include "cf_log.h"
#include "cf_stats.h"

/* Reads a cf_dns_source_stats_t counter, honoring reset_on_report. */
static unsigned long read_counter(atomic_ulong *v, int reset)
{
    return reset ? CF_ATOMIC_READ_AND_ZERO(*v) : CF_ATOMIC_READ(*v);
}

void cf_dns_stats_report(cf_dns_source_stats_t *stats, cf_redis_stats_t *redis_stats,
                         const cf_queue_t *q_rx, const cf_queue_t *q_redis, int reset_on_report)
{
    /* One value buffer per key rendered into the single cf_log() call: the
     * pointers must all stay live until cf_log() returns, so each needs its own
     * buffer (cf_log_u64 renders into the buffer it is handed). */
    char b_recv[24], b_kdrop[24], b_rxqd[24], b_rxqdep[24], b_trunc[24], b_rxbytes[24], b_snaptr[24];
    char b_skip[24], b_pfail[24], b_tcpp[24];
    char b_qpar[24], b_rpar[24];
    char b_emit[24], b_emcf[24], b_embk[24], b_emru[24], b_emun[24];
    char b_unans[24], b_unmat[24], b_pdrop[24], b_pcoll[24], b_rttinv[24], b_pdepth[24];
    char b_sampled[24];
    char b_pbfail[24], b_oversz[24], b_fqdrop[24], b_fqdep[24], b_redisdepth[24];
    char b_xadd[24], b_xerr[24], b_xlost[24], b_recon[24], b_xavg[24];

    /* rx-reader / pcap-replay counters (generic, libs/cloudflow-capture). */
    unsigned long packets_received = read_counter(&stats->rx.packets_received_total, reset_on_report);
    unsigned long packets_dropped = read_counter(&stats->rx.packets_dropped_total, reset_on_report);
    unsigned long rx_queue_drop = read_counter(&stats->rx.rx_queue_drop_total, reset_on_report);
    unsigned long packets_truncated =
        read_counter(&stats->rx.packets_truncated_total, reset_on_report);
    unsigned long rx_bytes_copied = read_counter(&stats->rx.rx_bytes_copied_total, reset_on_report);
    unsigned long packets_snap_truncated =
        read_counter(&stats->rx.packets_snap_truncated_total, reset_on_report);

    /* decap / parse / classify. */
    unsigned long packets_skipped = read_counter(&stats->packets_skipped_total, reset_on_report);
    unsigned long decode_parse_failure =
        read_counter(&stats->decode_parse_failure_total, reset_on_report);
    unsigned long dns_tcp_partial = read_counter(&stats->dns_tcp_partial_total, reset_on_report);

    /* correlation stage (DNS-D8 named counters). */
    unsigned long dns_queries_parsed = read_counter(&stats->dns_queries_parsed_total, reset_on_report);
    unsigned long dns_responses_parsed =
        read_counter(&stats->dns_responses_parsed_total, reset_on_report);
    unsigned long dns_txn_emitted =
        read_counter(&stats->dns_transactions_emitted_total, reset_on_report);
    unsigned long dns_txn_emitted_cf =
        read_counter(&stats->dns_transactions_emitted_client_facing_total, reset_on_report);
    unsigned long dns_txn_emitted_bk =
        read_counter(&stats->dns_transactions_emitted_backend_total, reset_on_report);
    unsigned long dns_txn_emitted_ru =
        read_counter(&stats->dns_transactions_emitted_recursion_upstream_total, reset_on_report);
    unsigned long dns_txn_emitted_un =
        read_counter(&stats->dns_transactions_emitted_unknown_total, reset_on_report);
    unsigned long dns_query_unanswered =
        read_counter(&stats->dns_query_unanswered_total, reset_on_report);
    unsigned long dns_response_unmatched =
        read_counter(&stats->dns_response_unmatched_total, reset_on_report);
    unsigned long dns_pending_drop = read_counter(&stats->dns_pending_drop_total, reset_on_report);
    unsigned long dns_pending_evicted_collision =
        read_counter(&stats->dns_pending_evicted_collision_total, reset_on_report);
    unsigned long dns_rtt_invalid = read_counter(&stats->dns_rtt_invalid_total, reset_on_report);
    unsigned long dns_sampled_out = read_counter(&stats->dns_sampled_out_total, reset_on_report);

    /* encode / queue counters. */
    unsigned long protobuf_encode_failure =
        read_counter(&stats->protobuf_encode_failure_total, reset_on_report);
    unsigned long events_oversize =
        read_counter(&stats->events_oversize_dropped_total, reset_on_report);
    unsigned long formatter_queue_drop =
        read_counter(&stats->formatter_queue_drop_total, reset_on_report);

    /* Gauges: always read live, never reset. The two queue depths are
     * re-sampled from the live queues so the line is current as of emission. */
    unsigned long rx_queue_depth = q_rx ? (unsigned long)cf_queue_length(q_rx)
                                        : CF_ATOMIC_READ(stats->rx.rx_queue_depth);
    unsigned long pending_table_depth = CF_ATOMIC_READ(stats->dns_pending_table_depth);
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
           "rx_bytes_copied_total", cf_log_u64(b_rxbytes, sizeof(b_rxbytes), rx_bytes_copied),
           "packets_snap_truncated_total",
           cf_log_u64(b_snaptr, sizeof(b_snaptr), packets_snap_truncated),
           "packets_skipped_total", cf_log_u64(b_skip, sizeof(b_skip), packets_skipped),
           "decode_parse_failure_total",
           cf_log_u64(b_pfail, sizeof(b_pfail), decode_parse_failure),
           "dns_tcp_partial_total", cf_log_u64(b_tcpp, sizeof(b_tcpp), dns_tcp_partial),
           "dns_queries_parsed_total", cf_log_u64(b_qpar, sizeof(b_qpar), dns_queries_parsed),
           "dns_responses_parsed_total", cf_log_u64(b_rpar, sizeof(b_rpar), dns_responses_parsed),
           "dns_transactions_emitted_total", cf_log_u64(b_emit, sizeof(b_emit), dns_txn_emitted),
           "dns_transactions_emitted_client_facing_total",
           cf_log_u64(b_emcf, sizeof(b_emcf), dns_txn_emitted_cf),
           "dns_transactions_emitted_backend_total",
           cf_log_u64(b_embk, sizeof(b_embk), dns_txn_emitted_bk),
           "dns_transactions_emitted_recursion_upstream_total",
           cf_log_u64(b_emru, sizeof(b_emru), dns_txn_emitted_ru),
           "dns_transactions_emitted_unknown_total",
           cf_log_u64(b_emun, sizeof(b_emun), dns_txn_emitted_un),
           "dns_query_unanswered_total",
           cf_log_u64(b_unans, sizeof(b_unans), dns_query_unanswered),
           "dns_response_unmatched_total",
           cf_log_u64(b_unmat, sizeof(b_unmat), dns_response_unmatched),
           "dns_pending_drop_total", cf_log_u64(b_pdrop, sizeof(b_pdrop), dns_pending_drop),
           "dns_pending_evicted_collision_total",
           cf_log_u64(b_pcoll, sizeof(b_pcoll), dns_pending_evicted_collision),
           "dns_rtt_invalid_total", cf_log_u64(b_rttinv, sizeof(b_rttinv), dns_rtt_invalid),
           "dns_pending_table_depth", cf_log_u64(b_pdepth, sizeof(b_pdepth), pending_table_depth),
           "dns_sampled_out_total", cf_log_u64(b_sampled, sizeof(b_sampled), dns_sampled_out),
           "protobuf_encode_failure_total",
           cf_log_u64(b_pbfail, sizeof(b_pbfail), protobuf_encode_failure),
           "events_oversize_dropped_total", cf_log_u64(b_oversz, sizeof(b_oversz), events_oversize),
           "formatter_queue_drop_total",
           cf_log_u64(b_fqdrop, sizeof(b_fqdrop), formatter_queue_drop),
           "formatter_queue_depth", cf_log_u64(b_fqdep, sizeof(b_fqdep), formatter_queue_depth),
           "redis_queue_depth", cf_log_u64(b_redisdepth, sizeof(b_redisdepth), redis_queue_depth),
           "xadd_total", cf_log_u64(b_xadd, sizeof(b_xadd), xadd_total),
           "xadd_errors_total", cf_log_u64(b_xerr, sizeof(b_xerr), xadd_errors),
           "events_lost_total", cf_log_u64(b_xlost, sizeof(b_xlost), events_lost),
           "redis_reconnects_total", cf_log_u64(b_recon, sizeof(b_recon), reconnects),
           "xadd_avg_latency_ns", cf_log_u64(b_xavg, sizeof(b_xavg), xadd_avg_latency_ns),
           NULL);
}
