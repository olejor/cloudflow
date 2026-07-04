#ifndef CF_SOURCE_DNS_SOURCE_STATS_H
#define CF_SOURCE_DNS_SOURCE_STATS_H

/* cf_dns_source_stats_t: the DNS source's application counter/gauge struct
 * (D8 in docs/architecture.md, DNS-D8 in docs/dns-source.md), shared by the
 * whole cloudflow-source-dns pipeline.
 *
 * It mirrors the DHCP source's cf_source_stats_t (sources/cloudflow-source-
 * dhcp/src/source_stats.h): the generic rx-level counters (packets_received/
 * dropped/truncated_total, rx_queue_drop_total, rx_queue_depth) live in
 * libs/cloudflow-capture's cf_rx_stats_t, embedded here as the `rx` member and
 * maintained by the shared rx-reader ring loop (cf_rx_reader) and the pcap-
 * replay reader (cf_pcap_replay). This struct adds the DNS event stage's own
 * counters -- the parse/classify, correlation (DNS-D8's named loss counters),
 * and encode/queue accounting -- alongside it. WP-DNS07's app shell owns
 * allocating/embedding this struct and emitting the periodic stats log line.
 *
 * Every field is atomic_ulong so any thread can update its own fields with the
 * CF_ATOMIC_* macros (libs/cloudflow-core/cf_stats.h) without locking; the
 * stats-reporting thread reads them with CF_ATOMIC_READ / CF_ATOMIC_READ_AND_
 * ZERO depending on config's stats.reset_on_report.
 *
 * The correlation-loss counters (dns_query_unanswered_total,
 * dns_response_unmatched_total, dns_pending_drop_total,
 * dns_pending_evicted_collision_total, dns_rtt_invalid_total,
 * dns_pending_table_depth) are snapshots of the correlator's own internal
 * cf_dns_correlator_stats_t (see correlation.h), stored here by the event
 * stage's emit path so the whole DNS-D8 loss picture appears in one stats line.
 *
 * Metric names match docs/dns-source.md's DNS-D8 counter list verbatim. */

#include <stdatomic.h>

#include "cf_rx_stats.h"

typedef struct {
    /* --- rx-reader / pcap-replay (generic, libs/cloudflow-capture) -----
     * packets_received_total, packets_dropped_total, rx_queue_drop_total,
     * rx_queue_depth, packets_truncated_total. */
    cf_rx_stats_t rx;

    /* --- decap / parse / classify (dns_stage) ----------------------------- */

    /* Frames decap/classification could not attribute to udp/53 or tcp/53
     * DNS (neither UDP nor TCP, BPF slippage, replay of non-DNS captures). */
    atomic_ulong packets_skipped_total;

    /* Frames whose bare DNS message cf_dns_parse could not turn into a usable
     * tree (< 12 bytes, unrecoverable header). The "decode-parse-failure"
     * counter. */
    atomic_ulong decode_parse_failure_total;

    /* DNS-D1: DNS-over-TCP messages whose 2-byte length prefix declares more
     * bytes than the single captured segment holds (multi-segment: large
     * responses, AXFR/IXFR). Counted and skipped, never reassembled. */
    atomic_ulong dns_tcp_partial_total;

    /* --- correlation stage (DNS-D8 named loss counters) -------------------- */

    /* Queries and responses successfully parsed and fed to the correlator. */
    atomic_ulong dns_queries_parsed_total;
    atomic_ulong dns_responses_parsed_total;

    /* Transactions actually emitted (post-sampling), across all outcomes,
     * with the per-role breakdown alongside (DNS-D7). */
    atomic_ulong dns_transactions_emitted_total;
    atomic_ulong dns_transactions_emitted_client_facing_total;
    atomic_ulong dns_transactions_emitted_backend_total;
    atomic_ulong dns_transactions_emitted_recursion_upstream_total;
    atomic_ulong dns_transactions_emitted_unknown_total;

    /* Correlator-derived snapshots (stored by the emit path): queries evicted
     * on timeout / free-drain, responses with no pending query, table-full
     * drops, same-key collision evictions, implausible RTTs, and the pending-
     * table depth gauge. */
    atomic_ulong dns_query_unanswered_total;
    atomic_ulong dns_response_unmatched_total;
    atomic_ulong dns_pending_drop_total;
    atomic_ulong dns_pending_evicted_collision_total;
    atomic_ulong dns_rtt_invalid_total;
    atomic_ulong dns_pending_table_depth; /* gauge */

    /* Transactions dropped by the sampling / emit policy (DNS-D8). Every 0
     * verdict from cf_dns_emit_decide() lands here so the loss stays visible. */
    atomic_ulong dns_sampled_out_total;

    /* --- encode / queue ---------------------------------------------------- */

    /* protobuf pack failures (a packed size of 0 from a non-empty event). */
    atomic_ulong protobuf_encode_failure_total;

    /* D11: events that still exceeded CLOUDFLOW_EVENT_MAX_SIZE even after
     * dropping the raw DNS payload(s), and were dropped rather than sent. */
    atomic_ulong events_oversize_dropped_total;

    /* Our own on_full drops pushing into the event stage -> redis-producer
     * queue (q_evt), per D9. */
    atomic_ulong formatter_queue_drop_total;

    /* Gauge: q_evt depth, sampled as events are pushed. */
    atomic_ulong formatter_queue_depth;
} cf_dns_source_stats_t;

#endif /* CF_SOURCE_DNS_SOURCE_STATS_H */
