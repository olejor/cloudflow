#ifndef CF_SOURCE_DHCP_STATS_H
#define CF_SOURCE_DHCP_STATS_H

/* WP-11: stats reporting for the cloudflow-source-dhcp application.
 *
 * The pipeline counter/gauge struct itself, cf_source_stats_t, already lives
 * in source_stats.h (defined under WP-08 so rx_reader.h/pcap_replay.h could
 * use it) -- this header does NOT redefine it, it just re-exports it and adds
 * the periodic reporting helper the main-thread stats loop calls.
 *
 * The Redis producer's own counters (cf_redis_stats_t) live in the redis
 * library (libs/cloudflow-redis/cf_redis_producer.h), not here; the reporting
 * helper below takes a pointer to one alongside the cf_source_stats_t so a
 * single log line can carry both halves of the pipeline's health, per the
 * WP-11 spec's "ONE cf_log line carrying all cf_source_stats_t counters AND
 * the redis producer's cf_redis_stats_t".
 */

#include "cf_redis_producer.h" /* cf_redis_stats_t */
#include "cf_queue.h"
#include "source_stats.h"      /* cf_source_stats_t (do NOT redefine) */

/* Emits exactly one structured cf_log(CF_LOG_INFO, ...) line carrying every
 * cf_source_stats_t counter/gauge plus the redis producer's cf_redis_stats_t
 * (xadd_total, xadd_errors_total, events_lost_total, reconnects, and the
 * derived average XADD latency in nanoseconds = xadd_latency_ns_total /
 * xadd_total). The two queue-depth gauges are re-sampled here from the live
 * queues (rx->formatter q and the redis input q) so the line always reflects
 * the moment it is emitted.
 *
 * When `reset_on_report` is non-zero, cumulative counters are read-and-zeroed
 * (CF_ATOMIC_READ_AND_ZERO) so each line reports the delta since the last;
 * gauges are always read without reset. reset_on_report affects only the
 * cf_source_stats_t counters this module owns emitting -- the cf_redis_stats_t
 * fields are always read cumulatively (the redis library owns them and other
 * readers may exist), matching the WP-11 spec's default of cumulative
 * reporting. */
void cf_stats_report(cf_source_stats_t *stats, cf_redis_stats_t *redis_stats,
                     const cf_queue_t *q_rx, const cf_queue_t *q_redis, int reset_on_report);

#endif
