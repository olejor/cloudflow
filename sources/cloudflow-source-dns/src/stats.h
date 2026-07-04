#ifndef CF_SOURCE_DNS_STATS_H
#define CF_SOURCE_DNS_STATS_H

/* WP-DNS07: stats reporting for the cloudflow-source-dns application.
 *
 * The pipeline counter/gauge struct itself, cf_dns_source_stats_t, lives in
 * dns_source_stats.h (so the shared rx-reader/pcap-replay path and the DNS
 * event stage can both use it) -- this header does NOT redefine it, it just
 * adds the periodic reporting helper the main-thread stats loop calls.
 *
 * The Redis producer's own counters (cf_redis_stats_t) live in the redis
 * library (libs/cloudflow-redis/cf_redis_producer.h); the reporting helper
 * below takes a pointer to one alongside the cf_dns_source_stats_t so a single
 * log line carries both halves of the pipeline's health, mirroring the DHCP
 * source's stats.{c,h}. */

#include "cf_redis_producer.h" /* cf_redis_stats_t */
#include "cf_queue.h"
#include "dns_source_stats.h"   /* cf_dns_source_stats_t (do NOT redefine) */

/* Emits exactly one structured cf_log(CF_LOG_INFO, ...) line carrying every
 * cf_dns_source_stats_t counter/gauge (the rx.* embedded fields, the DNS-D8
 * parse/classify/correlation/sampling counters, and the encode/queue
 * accounting) plus the redis producer's cf_redis_stats_t (xadd_total,
 * xadd_errors_total, events_lost_total, redis_reconnects_total, and the derived
 * average XADD latency in nanoseconds). The queue-depth gauges are re-sampled
 * here from the live queues (rx->stage q and the stage->redis q) so the line
 * always reflects the moment it is emitted.
 *
 * When `reset_on_report` is non-zero, cumulative counters are read-and-zeroed
 * (CF_ATOMIC_READ_AND_ZERO) so each line reports the delta since the last;
 * gauges are always read without reset. reset_on_report affects only the
 * cf_dns_source_stats_t counters this module emits -- the cf_redis_stats_t
 * fields are always read cumulatively (the redis library owns them and other
 * readers may exist). */
void cf_dns_stats_report(cf_dns_source_stats_t *stats, cf_redis_stats_t *redis_stats,
                         const cf_queue_t *q_rx, const cf_queue_t *q_redis, int reset_on_report);

#endif
