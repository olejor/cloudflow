#ifndef CF_SINK_SPLUNK_STATS_H
#define CF_SINK_SPLUNK_STATS_H

/* WP-17 -- counters + periodic structured stats line.
 *
 * Counter set from docs/splunk-output.md. Emitted as one JSON object
 * per line via cf_log (Convention 7). The HEC token is NEVER a field here. */

#include <stdatomic.h>
#include <stdint.h>

typedef struct {
    atomic_ulong splunk_delivery_total;
    atomic_ulong splunk_delivery_errors_total;
    atomic_ulong splunk_retry_total;
    atomic_ulong deadletter_total;
    atomic_ulong protobuf_decode_errors_total;
    atomic_ulong splunk_batch_size_last;
    atomic_ulong splunk_delivery_latency_ms_last;
    int64_t last_emit_mono_ns;
} cf_stats_t;

void cf_stats_init(cf_stats_t *s);

/* Emit one "stats" JSON log line now. */
void cf_stats_emit(cf_stats_t *s);

/* Emit only if at least `interval_ms` have passed since the last emit. */
void cf_stats_maybe_emit(cf_stats_t *s, int64_t interval_ms);

#endif
