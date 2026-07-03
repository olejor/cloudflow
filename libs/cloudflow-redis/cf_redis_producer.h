#ifndef CF_REDIS_PRODUCER_H
#define CF_REDIS_PRODUCER_H

/* WP-09 -- Redis XADD producer library.
 *
 * Destination-agnostic: drains cf_event_item_t from a cf_queue_t and
 * delivers them to Redis Streams via pipelined XADD, with reconnect/backoff
 * and explicit loss accounting. Nothing DHCP-specific lives here -- see
 * docs/design/03-source-dhcp.md (WP-09 section) for the full behavior spec
 * this implements, and docs/redis-streams.md for the entry format contract.
 *
 * Structure lifted from import/network_syslog_collector/src/redis.c (the
 * pipeline-accumulate-then-drain loop, reconnect rate-limiting, drop
 * accounting), adapted to a single thread (D4) and plain hiredis (D3)
 * instead of hiredis-cluster, with binary-safe payloads instead of JSON.
 *
 * Threading model: like rx_reader (WP-08), this is a process-wide singleton
 * -- cf_redis_producer_start() spawns exactly one thread; a second call
 * before cf_redis_producer_stop() fails. cf_redis_producer_stop() is
 * idempotent and joins the thread.
 */

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#include "cf_queue.h"
#include "cloudflow.h"

/* Pipeline sizing (see docs/design/03-source-dhcp.md WP-09): the producer
 * keeps a fixed array of up to pipeline_max in-flight cf_event_item_t
 * copies (no per-event heap allocation in steady state beyond what hiredis
 * itself does for its output/input buffers). cf_event_item_t is
 * approximately CLOUDFLOW_EVENT_MAX_SIZE (8192) bytes, so the producer's
 * resident memory for this array is
 * pipeline_max * sizeof(cf_event_item_t) bytes -- at the capped maximum
 * (4096 * ~8200) that is roughly 32 MiB; at the default (512) roughly 4 MiB.
 */
#define CF_REDIS_PRODUCER_PIPELINE_MAX_CAP 4096u
#define CF_REDIS_PRODUCER_DEFAULT_PIPELINE_MAX 512u
#define CF_REDIS_PRODUCER_DEFAULT_FLUSH_INTERVAL_MS 100u

/* Atomic counters, per docs/design/03-source-dhcp.md's WP-09 "Counters"
 * bullet and D8 (docs/design/00-overview.md). Built from the CF_ATOMIC_*
 * primitives in cf_stats.h; read with CF_ATOMIC_READ() (or
 * CF_ATOMIC_READ_AND_ZERO() if a caller wants reset-on-report semantics)
 * from a stats-reporting thread.
 *
 * There is no separate redis_queue_depth field here: that counter is a
 * gauge over the *input* queue (cfg->in), which the caller already owns and
 * can sample directly at stats time with cf_queue_length(cfg->in) --
 * duplicating it into this struct would just be two numbers that can drift
 * out of sync. Sample cf_queue_length() on the same cf_queue_t pointer
 * passed as cf_redis_producer_config_t.in.
 */
typedef struct {
    atomic_ulong xadd_total;
    atomic_ulong xadd_errors_total;
    atomic_ulong xadd_latency_ns_total; /* sum, for computing an average */
    atomic_ulong redis_reconnects_total;
    atomic_ulong events_lost_total;
} cf_redis_stats_t;

typedef struct {
    const char *const *endpoints; /* "host:port" strings, tried in order (D3) */
    size_t endpoint_count;
    long long maxlen_approx;     /* XADD MAXLEN ~ value; 0 = no trim */
    uint32_t pipeline_max;       /* default 512, capped at 4096 */
    uint32_t flush_interval_ms;  /* default 100 */
    cf_queue_t *in;              /* of cf_event_item_t */
    cf_redis_stats_t *stats;
} cf_redis_producer_config_t;

/* Spawns the producer thread. `cfg` is copied internally (its `endpoints`
 * array and the strings it points to, `in`, and `stats` must stay valid for
 * the life of the run -- i.e. until after cf_redis_producer_stop() returns).
 * pipeline_max == 0 defaults to CF_REDIS_PRODUCER_DEFAULT_PIPELINE_MAX;
 * values above CF_REDIS_PRODUCER_PIPELINE_MAX_CAP are clamped down.
 * flush_interval_ms == 0 defaults to
 * CF_REDIS_PRODUCER_DEFAULT_FLUSH_INTERVAL_MS.
 *
 * Returns 0 on success, -1 on invalid config or if a producer is already
 * running (call cf_redis_producer_stop() first).
 */
int cf_redis_producer_start(const cf_redis_producer_config_t *cfg);

/* Requests shutdown (independent of the process-wide cf_stop_notify/
 * cf_stop_notified flag in cf_sync.h -- this works even if nothing ever
 * calls cf_stop_notify()), drains the input queue and flushes the pipeline
 * up to a 5s deadline, then joins the thread. Idempotent: safe to call when
 * no producer is running. */
void cf_redis_producer_stop(void);

#endif
