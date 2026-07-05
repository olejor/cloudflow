#ifndef CF_CAPTURE_RX_STATS_H
#define CF_CAPTURE_RX_STATS_H

/* cf_rx_stats_t: the generic rx-level atomic counters/gauges shared by every
 * capture-based source (D8, docs/architecture.md). Split out of
 * sources/cloudflow-source-dhcp/src/source_stats.h into libs/cloudflow-capture
 * so a second source (DNS) reuses the exact same rx accounting the rx-reader
 * ring loop and the pcap-replay reader maintain (synergy item A2). A source's
 * own application-specific counter struct (e.g. cf_source_stats_t) embeds one
 * of these as a `rx` member and keeps its formatter/producer counters
 * alongside it.
 *
 * Every field is atomic_ulong so any thread can update its own fields with
 * the CF_ATOMIC_* macros (libs/cloudflow-core/cf_stats.h) without locking;
 * the stats-reporting thread reads them with CF_ATOMIC_READ /
 * CF_ATOMIC_READ_AND_ZERO. Metric names match AGENTS.md's "Useful CloudFlow
 * service metrics" list. */

#include <stdatomic.h>

/* cf_packet_item_t.flags bits. Defined here (alongside the rx stats the ring
 * loop and pcap replay maintain) rather than in cloudflow.h because
 * cf_packet_item_t's owning header is a different library; the flag constant
 * belongs with the capture layer that sets it. */
#define CF_PACKET_FLAG_TRUNCATED 0x00000001u

typedef struct {
    /* Every frame observed (ring capture) or read (pcap replay), whether
     * or not it was successfully queued. */
    atomic_ulong packets_received_total;

    /* Kernel-side drops, sampled from getsockopt(PACKET_STATISTICS) each
     * epoll timeout tick. Always 0 for pcap replay (no kernel ring). */
    atomic_ulong packets_dropped_total;

    /* on_full drops pushing into the rx -> formatter queue (q_pkt), per D9. */
    atomic_ulong rx_queue_drop_total;

    /* Gauge: q_pkt depth, sampled at the same time as packets_dropped_total. */
    atomic_ulong rx_queue_depth;

    /* Frames whose captured bytes exceeded CLOUDFLOW_PACKET_MAX_SIZE and
     * were copied truncated (CF_PACKET_FLAG_TRUNCATED set). */
    atomic_ulong packets_truncated_total;

    /* Total bytes actually copied out of the ring/pcap into packet items
     * (sum of captured_len). Divided by packets_received_total this is the
     * mean captured bytes/packet -- the measurement that shows how much of the
     * fixed ~2 KB packet-item copy is real payload vs. wasted movement, which
     * is the evidence for the descriptor-queue/slab work. */
    atomic_ulong rx_bytes_copied_total;
} cf_rx_stats_t;

#endif
