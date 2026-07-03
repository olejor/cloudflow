#include "cf_redis_producer.h"

#include <hiredis/hiredis.h>

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "cf_log.h"
#include "cf_stats.h"
#include "cf_sync.h"
#include "cf_time.h"

/* ---- tuning constants -------------------------------------------------- */

#define CF_REDIS_CONNECT_TIMEOUT_SEC 3
#define CF_REDIS_BACKOFF_INITIAL_NS  (100LL * 1000 * 1000)   /* 100ms */
#define CF_REDIS_BACKOFF_MAX_NS      (5000LL * 1000 * 1000)  /* 5s cap */
#define CF_REDIS_SHUTDOWN_DEADLINE_NS (5000LL * 1000 * 1000) /* 5s drain budget */
#define CF_REDIS_IDLE_SLEEP_NS       (5LL * 1000 * 1000)     /* 5ms poll when input queue is empty */
#define CF_REDIS_LOG_RATE_LIMIT_NS   (1000LL * 1000 * 1000)  /* 1s between repeated log lines */
#define CF_REDIS_BACKOFF_SLEEP_CHUNK_NS (50LL * 1000 * 1000) /* 50ms -- keeps backoff sleeps interruptible */

/* Entry format, per docs/redis-streams.md and the WP-09 spec. */
#define CF_REDIS_SCHEMA_NAME "cloudflow.v1.CloudFlowEvent"
#define CF_REDIS_SCHEMA_VERSION 1
#define CF_REDIS_ENCODING_NAME "protobuf"

/* ---- singleton state ---------------------------------------------------
 *
 * cf_redis_producer_start()/stop() take no context handle (matching the
 * exact signatures in docs/design/03-source-dhcp.md), so -- like
 * rx_reader_start()/stop() in WP-08 -- exactly one producer instance may
 * run at a time per process. The thread owns g_cfg for its entire run (a
 * private copy taken at start() time); nothing else touches it while the
 * thread is alive.
 */
static pthread_t g_thread;
static atomic_int g_running = 0;
static atomic_int g_stop_local = 0;
static cf_redis_producer_config_t g_cfg;

/* Rate-limited-log timestamps. Touched only by the single producer thread
 * (never concurrently with itself -- start()/stop() are not reentrant), so
 * plain statics are fine without atomics. */
static int64_t g_last_connect_fail_log;
static int64_t g_last_invalid_stream_log;
static int64_t g_last_append_error_log;
static int64_t g_last_xadd_error_log;
static int64_t g_last_retry_fail_log;

static int producer_should_stop(void)
{
    return cf_stop_notified() || atomic_load(&g_stop_local);
}

static void log_rate_limited_kv(int64_t *last_log_mono, cf_log_level_t level,
                                 const char *msg, const char *key, const char *value)
{
    int64_t now = cf_now_mono_nano();

    if (*last_log_mono != 0 && now - *last_log_mono < CF_REDIS_LOG_RATE_LIMIT_NS)
        return;

    *last_log_mono = now;

    if (key)
        cf_log(level, msg, key, value, NULL);
    else
        cf_log(level, msg, NULL);
}

/* ---- connection management ---------------------------------------------- */

/* Splits "host:port" at the last ':' (good enough for hostnames/IPv4 -- v0.1
 * does not support bare, unbracketed IPv6 literals, matching the simple
 * endpoint list D3 describes). Returns 0 on success. */
static int parse_endpoint(const char *endpoint, char *host, size_t host_cap, int *port)
{
    const char *colon;
    size_t host_len;
    char *end = NULL;
    long parsed;

    if (!endpoint)
        return -1;

    colon = strrchr(endpoint, ':');
    if (!colon || colon == endpoint)
        return -1;

    host_len = (size_t)(colon - endpoint);
    if (host_len == 0 || host_len >= host_cap)
        return -1;

    memcpy(host, endpoint, host_len);
    host[host_len] = '\0';

    parsed = strtol(colon + 1, &end, 10);
    if (end == colon + 1 || *end != '\0' || parsed <= 0 || parsed > 65535)
        return -1;

    *port = (int)parsed;

    return 0;
}

static redisContext *try_connect_one(const char *endpoint)
{
    struct timeval tv;
    char host[256];
    int port;
    redisContext *ctx;

    tv.tv_sec = CF_REDIS_CONNECT_TIMEOUT_SEC;
    tv.tv_usec = 0;

    if (parse_endpoint(endpoint, host, sizeof(host), &port) != 0) {
        log_rate_limited_kv(&g_last_connect_fail_log, CF_LOG_ERROR,
                             "redis producer: unparseable endpoint", "endpoint", endpoint);
        return NULL;
    }

    ctx = redisConnectWithTimeout(host, port, tv);
    if (!ctx)
        return NULL;

    if (ctx->err) {
        redisFree(ctx);
        return NULL;
    }

    return ctx;
}

/* Sleeps up to `backoff_ns`, in small interruptible chunks, bailing early if
 * the deadline passes or (when `bail_on_stop`) a stop is requested. */
static void sleep_backoff(int64_t backoff_ns, int64_t deadline_mono, int bail_on_stop)
{
    int64_t remaining = backoff_ns;

    while (remaining > 0) {
        int64_t chunk;

        if (cf_now_mono_nano() >= deadline_mono)
            return;
        if (bail_on_stop && producer_should_stop())
            return;

        chunk = remaining < CF_REDIS_BACKOFF_SLEEP_CHUNK_NS ? remaining : CF_REDIS_BACKOFF_SLEEP_CHUNK_NS;
        cf_sleep_ns(chunk);
        remaining -= chunk;
    }
}

/* Tries endpoints in order (3s connect timeout each), cycling through the
 * list and backing off 100ms doubling to a 5s cap between full cycles, per
 * the WP-09 "Connect" behavior. Bails out (returning NULL) once
 * `deadline_mono` (CLOCK_MONOTONIC) passes, or -- when `bail_on_stop` is set
 * -- as soon as a stop is requested; the caller picks whichever applies:
 * steady-state reconnect passes deadline_mono = INT64_MAX and
 * bail_on_stop = 1 (stop should interrupt an otherwise-unbounded retry
 * loop); the shutdown drain passes the real 5s deadline and
 * bail_on_stop = 0 (stop is already known true -- that's why we're
 * draining -- so it must not itself cut the attempt short). */
static redisContext *connect_with_backoff(const cf_redis_producer_config_t *cfg,
                                           size_t *endpoint_idx, int64_t *backoff_ns,
                                           int count_as_reconnect,
                                           int64_t deadline_mono, int bail_on_stop)
{
    for (;;) {
        size_t tries;

        for (tries = 0; tries < cfg->endpoint_count; tries++) {
            const char *ep;
            redisContext *ctx;

            if (cf_now_mono_nano() >= deadline_mono)
                return NULL;
            if (bail_on_stop && producer_should_stop())
                return NULL;

            ep = cfg->endpoints[(*endpoint_idx) % cfg->endpoint_count];
            (*endpoint_idx)++;

            ctx = try_connect_one(ep);
            if (ctx) {
                if (count_as_reconnect)
                    CF_ATOMIC_INC(cfg->stats->redis_reconnects_total);
                *backoff_ns = CF_REDIS_BACKOFF_INITIAL_NS;
                return ctx;
            }
        }

        if (cf_now_mono_nano() >= deadline_mono)
            return NULL;
        if (bail_on_stop && producer_should_stop())
            return NULL;

        log_rate_limited_kv(&g_last_connect_fail_log, CF_LOG_WARN,
                             "redis producer: all endpoints unreachable, backing off", NULL, NULL);

        sleep_backoff(*backoff_ns, deadline_mono, bail_on_stop);

        *backoff_ns *= 2;
        if (*backoff_ns > CF_REDIS_BACKOFF_MAX_NS)
            *backoff_ns = CF_REDIS_BACKOFF_MAX_NS;
    }
}

/* ---- pipeline ------------------------------------------------------------ */

/* Appends one XADD command to ctx's output buffer (redisAppendCommand does
 * not write to the socket yet -- see flush_pipeline()). event_type and
 * payload go over the wire via %b (binary-safe: embedded NULs and
 * non-terminated buffers are both fine) rather than %s, since
 * cf_event_item_t.event_type is a fixed-size buffer whose NUL-termination
 * is the formatter's responsibility, not this library's to assume. Returns
 * 0 on success, -1 if the stream id is invalid or the append itself fails
 * (e.g. out of memory formatting the command). */
static int append_xadd(redisContext *ctx, const cf_redis_producer_config_t *cfg,
                        const cf_event_item_t *item)
{
    const char *stream;
    size_t event_type_len;
    int rc;

    if (!ctx)
        return -1;

    stream = cf_stream_name(item->stream_id);
    if (!stream)
        return -1;

    event_type_len = strnlen(item->event_type, sizeof(item->event_type));

    if (cfg->maxlen_approx > 0) {
        rc = redisAppendCommand(ctx,
            "XADD %s MAXLEN ~ %lld * schema %s version %d encoding %s event_type %b payload %b",
            stream, cfg->maxlen_approx,
            CF_REDIS_SCHEMA_NAME, CF_REDIS_SCHEMA_VERSION, CF_REDIS_ENCODING_NAME,
            (const char *)item->event_type, event_type_len,
            (const char *)item->payload, (size_t)item->payload_len);
    } else {
        rc = redisAppendCommand(ctx,
            "XADD %s * schema %s version %d encoding %s event_type %b payload %b",
            stream,
            CF_REDIS_SCHEMA_NAME, CF_REDIS_SCHEMA_VERSION, CF_REDIS_ENCODING_NAME,
            (const char *)item->event_type, event_type_len,
            (const char *)item->payload, (size_t)item->payload_len);
    }

    return rc == REDIS_OK ? 0 : -1;
}

/* Drains up to `count` replies already appended to ctx's pipeline (this is
 * also where redisGetReply() actually flushes the output buffer to the
 * socket, on its first call). Per-command error replies are counted and
 * rate-limit logged but do not stop the drain; an I/O error (redisGetReply
 * itself failing) does, since it means the connection is no longer usable
 * -- the caller retries the tail. Returns the number of replies actually
 * drained (== count on full success). */
static size_t flush_pipeline(redisContext *ctx, cf_redis_stats_t *stats, size_t count, int *io_error)
{
    size_t i;
    int64_t t_prev = cf_now_mono_nano();

    *io_error = 0;

    for (i = 0; i < count; i++) {
        redisReply *reply = NULL;
        int rc = redisGetReply(ctx, (void **)&reply);
        int64_t now;

        if (rc != REDIS_OK || !reply) {
            *io_error = 1;
            if (reply)
                freeReplyObject(reply);
            break;
        }

        now = cf_now_mono_nano();
        CF_ATOMIC_ADD(stats->xadd_latency_ns_total, (unsigned long)(now - t_prev));
        t_prev = now;

        if (reply->type == REDIS_REPLY_ERROR) {
            CF_ATOMIC_INC(stats->xadd_errors_total);
            log_rate_limited_kv(&g_last_xadd_error_log, CF_LOG_WARN,
                                 "redis producer: XADD error reply", "error", reply->str);
        } else {
            CF_ATOMIC_INC(stats->xadd_total);
        }

        freeReplyObject(reply);
    }

    return i;
}

/* Flushes the current in-flight batch. On success, empties it. On an I/O
 * error mid-drain, per the WP-09 "retry once" semantics: the context is
 * torn down, a fresh one is established (reconnecting -- bumping
 * redis_reconnects_total), and the *unacknowledged tail* (the slice whose
 * replies were never received) is re-appended and drained exactly once more
 * against the new connection. Double delivery of the acknowledged prefix is
 * possible if the ack itself was lost in flight, which the spec explicitly
 * accepts (downstream dedupes on event_id); silent loss is not accepted, so
 * anything still unacknowledged after that single retry is counted into
 * events_lost_total and dropped. */
static void do_flush(redisContext **ctx_ptr, const cf_redis_producer_config_t *cfg,
                      cf_event_item_t *inflight, size_t *inflight_count,
                      size_t *endpoint_idx, int64_t *backoff_ns,
                      int stopping, int64_t shutdown_deadline_mono)
{
    int io_error = 0;
    size_t drained;
    size_t unacked;
    int64_t deadline;
    int bail_on_stop;

    drained = flush_pipeline(*ctx_ptr, cfg->stats, *inflight_count, &io_error);

    if (!io_error) {
        *inflight_count = 0;
        return;
    }

    redisFree(*ctx_ptr);
    *ctx_ptr = NULL;

    unacked = *inflight_count - drained;
    *inflight_count = 0;

    if (unacked == 0)
        return;

    if (drained > 0)
        memmove(inflight, inflight + drained, unacked * sizeof(inflight[0]));

    deadline = stopping ? shutdown_deadline_mono : INT64_MAX;
    bail_on_stop = !stopping;

    *ctx_ptr = connect_with_backoff(cfg, endpoint_idx, backoff_ns, 1, deadline, bail_on_stop);

    if (!*ctx_ptr) {
        char buf[32];

        CF_ATOMIC_ADD(cfg->stats->events_lost_total, (unsigned long)unacked);
        log_rate_limited_kv(&g_last_retry_fail_log, CF_LOG_ERROR,
                             "redis producer: reconnect failed, dropping unacknowledged events",
                             "count", cf_log_u64(buf, sizeof(buf), unacked));
        return;
    }

    {
        size_t appended = 0;
        size_t i;
        int io_error2 = 0;
        size_t drained2;
        size_t lost;

        for (i = 0; i < unacked; i++) {
            if (append_xadd(*ctx_ptr, cfg, &inflight[i]) != 0)
                break;
            appended++;
        }

        lost = unacked - appended;

        drained2 = appended > 0 ? flush_pipeline(*ctx_ptr, cfg->stats, appended, &io_error2) : 0;

        if (io_error2) {
            redisFree(*ctx_ptr);
            *ctx_ptr = NULL;
            lost += appended - drained2;
        }

        if (lost > 0) {
            char buf[32];

            CF_ATOMIC_ADD(cfg->stats->events_lost_total, (unsigned long)lost);
            log_rate_limited_kv(&g_last_retry_fail_log, CF_LOG_ERROR,
                                 "redis producer: retry failed, dropping unacknowledged events",
                                 "count", cf_log_u64(buf, sizeof(buf), lost));
        }
    }
}

/* ---- main loop ------------------------------------------------------------ */

static void *cf_redis_producer_thread_main(void *arg)
{
    const cf_redis_producer_config_t *cfg = arg;
    redisContext *ctx;
    size_t endpoint_idx = 0;
    int64_t backoff_ns = CF_REDIS_BACKOFF_INITIAL_NS;
    cf_event_item_t *inflight;
    size_t inflight_count = 0;
    int64_t batch_start_mono = 0;
    int64_t shutdown_deadline_mono = -1;

    inflight = calloc(cfg->pipeline_max, sizeof(*inflight));
    if (!inflight) {
        cf_log(CF_LOG_ERROR, "redis producer: in-flight buffer allocation failed", NULL);
        return NULL;
    }

    /* Initial connect: unbounded retry (steady-state backoff), but a stop
     * request before the very first connection succeeds must still let the
     * thread exit promptly. */
    ctx = connect_with_backoff(cfg, &endpoint_idx, &backoff_ns, 0, INT64_MAX, 1);

    for (;;) {
        int stopping = producer_should_stop();
        int64_t deadline;
        int bail_on_stop;
        int should_flush;

        if (stopping && shutdown_deadline_mono < 0)
            shutdown_deadline_mono = cf_now_mono_nano() + CF_REDIS_SHUTDOWN_DEADLINE_NS;

        if (stopping && inflight_count == 0 && cf_queue_length(cfg->in) == 0)
            break;

        if (stopping && cf_now_mono_nano() >= shutdown_deadline_mono) {
            size_t remaining = cf_queue_length(cfg->in);

            if (remaining > 0) {
                cf_event_item_t tmp;

                while (cf_queue_pop(cfg->in, &tmp) == 0)
                    ; /* drain unsent items without attempting delivery */
                CF_ATOMIC_ADD(cfg->stats->events_lost_total, (unsigned long)remaining);
            }

            if (inflight_count > 0) {
                CF_ATOMIC_ADD(cfg->stats->events_lost_total, (unsigned long)inflight_count);
                inflight_count = 0;
            }

            break;
        }

        if (stopping) {
            deadline = shutdown_deadline_mono;
            bail_on_stop = 0;
        } else {
            deadline = INT64_MAX;
            bail_on_stop = 1;
        }

        if (!ctx) {
            ctx = connect_with_backoff(cfg, &endpoint_idx, &backoff_ns, 1, deadline, bail_on_stop);
            if (!ctx)
                continue; /* reassess stop/deadline state at the top of the loop */
        }

        if (inflight_count < cfg->pipeline_max) {
            cf_event_item_t item;
            int rc = cf_queue_pop(cfg->in, &item);

            if (rc == 0) {
                if (append_xadd(ctx, cfg, &item) == 0) {
                    if (inflight_count == 0)
                        batch_start_mono = cf_now_mono_nano();
                    inflight[inflight_count++] = item;
                } else if (!cf_stream_name(item.stream_id)) {
                    CF_ATOMIC_INC(cfg->stats->events_lost_total);
                    log_rate_limited_kv(&g_last_invalid_stream_log, CF_LOG_WARN,
                                         "redis producer: dropping event with invalid stream id",
                                         NULL, NULL);
                } else {
                    CF_ATOMIC_INC(cfg->stats->events_lost_total);
                    log_rate_limited_kv(&g_last_append_error_log, CF_LOG_ERROR,
                                         "redis producer: XADD append failed", NULL, NULL);
                }
            } else if (!stopping) {
                cf_sleep_ns(CF_REDIS_IDLE_SLEEP_NS);
            }
        }

        should_flush = 0;
        if (inflight_count >= cfg->pipeline_max)
            should_flush = 1;
        else if (inflight_count > 0 && stopping)
            should_flush = 1;
        else if (inflight_count > 0 &&
                 (cf_now_mono_nano() - batch_start_mono) >= (int64_t)cfg->flush_interval_ms * 1000000LL)
            should_flush = 1;

        if (should_flush)
            do_flush(&ctx, cfg, inflight, &inflight_count, &endpoint_idx, &backoff_ns,
                     stopping, shutdown_deadline_mono);
    }

    if (ctx)
        redisFree(ctx);
    free(inflight);

    return NULL;
}

/* ---- public API ------------------------------------------------------------ */

int cf_redis_producer_start(const cf_redis_producer_config_t *cfg)
{
    cf_redis_producer_config_t local;

    if (!cfg || !cfg->endpoints || cfg->endpoint_count == 0 || !cfg->in || !cfg->stats)
        return -1;

    if (atomic_load(&g_running))
        return -1;

    local = *cfg;

    if (local.pipeline_max == 0)
        local.pipeline_max = CF_REDIS_PRODUCER_DEFAULT_PIPELINE_MAX;
    if (local.pipeline_max > CF_REDIS_PRODUCER_PIPELINE_MAX_CAP)
        local.pipeline_max = CF_REDIS_PRODUCER_PIPELINE_MAX_CAP;
    if (local.flush_interval_ms == 0)
        local.flush_interval_ms = CF_REDIS_PRODUCER_DEFAULT_FLUSH_INTERVAL_MS;

    g_cfg = local;

    atomic_store(&g_stop_local, 0);
    g_last_connect_fail_log = 0;
    g_last_invalid_stream_log = 0;
    g_last_append_error_log = 0;
    g_last_xadd_error_log = 0;
    g_last_retry_fail_log = 0;

    if (pthread_create(&g_thread, NULL, cf_redis_producer_thread_main, &g_cfg) != 0)
        return -1;

    atomic_store(&g_running, 1);

    return 0;
}

void cf_redis_producer_stop(void)
{
    if (!atomic_load(&g_running))
        return;

    atomic_store(&g_stop_local, 1);
    pthread_join(g_thread, NULL);
    atomic_store(&g_running, 0);
}
