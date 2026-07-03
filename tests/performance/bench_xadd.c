/* WP-15 -- XADD benchmark.
 *
 * Standalone binary linking libcloudflow-redis + libcloudflow-core: a
 * generator thread fills a cf_queue_t as fast as it accepts with synthetic
 * cf_event_item_t (alternating both DHCP stream ids, a patterned payload of
 * the configured size, event_type set), the *real* cf_redis_producer
 * (WP-09) drains it against a real Redis for a fixed duration, then both
 * are stopped, the queue is drained, and one machine-readable summary line
 * is printed.
 *
 * Producer lifecycle note (see docs/design/03-source-dhcp.md WP-09 and
 * libs/cloudflow-redis/tests/cf_redis_producer_test.c): this binary never
 * calls cf_stop_notify(). Shutdown relies solely on cf_redis_producer_stop()
 * (its own producer-local stop flag, independent of the process-wide
 * cf_stop_notified() flag) draining and flushing the pipeline before it
 * returns. cf_stop_install_signal_handlers() is still installed so Ctrl-C
 * during a long run stops the generator promptly instead of hanging until
 * --duration-s elapses; it is not required for a normal, uninterrupted run.
 */

#include <getopt.h>
#include <hiredis/hiredis.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cf_queue.h"
#include "cf_redis_producer.h"
#include "cf_stats.h"
#include "cf_sync.h"
#include "cf_time.h"
#include "cloudflow.h"

/* ---- defaults, per the WP-15 spec ---------------------------------------- */

#define DEFAULT_PAYLOAD_SIZE 2048u
#define DEFAULT_PIPELINE 512u
#define DEFAULT_DURATION_S 10u
#define DEFAULT_REDIS_ENDPOINT "127.0.0.1:6379"
#define DEFAULT_FLUSH_INTERVAL_MS 100u

#define QUEUE_CAPACITY_MIN 1024u
#define QUEUE_CAPACITY_MAX 16384u
#define QUEUE_CAPACITY_MULT 8u

typedef struct {
    uint32_t payload_size;
    uint32_t pipeline;
    uint32_t duration_s;
    uint32_t flush_interval_ms;
    char redis_endpoint[256];
} bench_config_t;

/* ---- generator thread ----------------------------------------------------- */

typedef struct {
    cf_queue_t *queue;
    uint32_t payload_size;
    atomic_int stop;
} generator_ctx_t;

static void fill_item(cf_event_item_t *item, cf_stream_id_t stream_id, uint32_t payload_size,
                      unsigned int seed)
{
    uint32_t i;

    memset(item, 0, sizeof(*item));
    item->observed_time_unix_nano = cf_now_unix_nano();
    item->stream_id = stream_id;
    item->protocol = (stream_id == CF_STREAM_DHCPV4) ? CF_PROTO_DHCPV4 : CF_PROTO_DHCPV6;
    snprintf(item->event_type, sizeof(item->event_type), "bench-xadd");
    item->payload_len = payload_size;

    for (i = 0; i < payload_size; i++)
        item->payload[i] = (uint8_t)((seed + i) & 0xFFu);
}

static void *generator_thread_main(void *arg)
{
    generator_ctx_t *ctx = arg;
    unsigned int seed = 0;

    while (!atomic_load(&ctx->stop)) {
        cf_event_item_t item;
        cf_stream_id_t stream_id = (seed % 2 == 0) ? CF_STREAM_DHCPV4 : CF_STREAM_DHCPV6;
        int rc;

        fill_item(&item, stream_id, ctx->payload_size, seed);
        seed++;

        /* Fill "as fast as the queue accepts": busy-retry on a full queue,
         * matching the push pattern in
         * libs/cloudflow-redis/tests/cf_redis_producer_test.c, but bail out
         * promptly once told to stop (or on process-wide stop, e.g. from a
         * SIGINT/SIGTERM caught by cf_stop_install_signal_handlers()) rather
         * than spinning forever if the consumer side has already gone away. */
        do {
            rc = cf_queue_push(ctx->queue, &item);
        } while (rc == 1 && !atomic_load(&ctx->stop) && !cf_stop_notified());
    }

    return NULL;
}

/* ---- pre-run stream trim --------------------------------------------------- */

/* Splits "host:port" the same way cf_redis_producer.c's internal
 * parse_endpoint() does (last ':' wins), just so this binary can open its
 * own raw hiredis connection to DEL the two DHCP streams before each run --
 * keeps Redis memory bounded across scripts/benchmark-xadd.sh's whole
 * payload x pipeline matrix instead of accumulating entries run over run. */
static int parse_endpoint(const char *endpoint, char *host, size_t host_cap, int *port)
{
    const char *colon = strrchr(endpoint, ':');
    size_t host_len;
    char *end = NULL;
    long parsed;

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

/* Best-effort: a failure here does not abort the benchmark (the producer
 * will surface connectivity problems itself via reconnects/backoff), it
 * just means stream trimming did not happen for this run. */
static void trim_streams(const char *endpoint)
{
    char host[256];
    int port;
    struct timeval tv;
    redisContext *ctx;
    redisReply *r;

    if (parse_endpoint(endpoint, host, sizeof(host), &port) != 0) {
        fprintf(stderr, "bench_xadd: warning: could not parse --redis endpoint '%s' for pre-run trim\n",
                endpoint);
        return;
    }

    tv.tv_sec = 2;
    tv.tv_usec = 0;

    ctx = redisConnectWithTimeout(host, port, tv);
    if (!ctx || ctx->err) {
        fprintf(stderr, "bench_xadd: warning: could not connect to %s for pre-run stream trim (%s)\n",
                endpoint, ctx ? ctx->errstr : "connection failed");
        if (ctx)
            redisFree(ctx);
        return;
    }

    r = redisCommand(ctx, "DEL %s %s", cf_stream_name(CF_STREAM_DHCPV4), cf_stream_name(CF_STREAM_DHCPV6));
    if (r)
        freeReplyObject(r);

    redisFree(ctx);
}

/* ---- CLI ------------------------------------------------------------------- */

static void print_usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s [--payload-size N] [--pipeline N] [--duration-s N]\n"
            "          [--redis host:port] [--flush-interval-ms N]\n"
            "\n"
            "  --payload-size N       synthetic event payload size in bytes (default %u, max %u)\n"
            "  --pipeline N           producer pipeline_max (default %u, max %u)\n"
            "  --duration-s N         benchmark run duration in seconds (default %u)\n"
            "  --redis host:port      Redis endpoint (default %s)\n"
            "  --flush-interval-ms N  producer flush interval in ms (default %u)\n",
            prog, DEFAULT_PAYLOAD_SIZE, CLOUDFLOW_EVENT_MAX_SIZE, DEFAULT_PIPELINE,
            CF_REDIS_PRODUCER_PIPELINE_MAX_CAP, DEFAULT_DURATION_S, DEFAULT_REDIS_ENDPOINT,
            DEFAULT_FLUSH_INTERVAL_MS);
}

static int parse_args(int argc, char **argv, bench_config_t *cfg)
{
    enum {
        OPT_PAYLOAD_SIZE = 1000,
        OPT_PIPELINE,
        OPT_DURATION_S,
        OPT_REDIS,
        OPT_FLUSH_INTERVAL_MS,
        OPT_HELP,
    };

    static const struct option long_opts[] = {
        {"payload-size", required_argument, NULL, OPT_PAYLOAD_SIZE},
        {"pipeline", required_argument, NULL, OPT_PIPELINE},
        {"duration-s", required_argument, NULL, OPT_DURATION_S},
        {"redis", required_argument, NULL, OPT_REDIS},
        {"flush-interval-ms", required_argument, NULL, OPT_FLUSH_INTERVAL_MS},
        {"help", no_argument, NULL, OPT_HELP},
        {NULL, 0, NULL, 0},
    };

    cfg->payload_size = DEFAULT_PAYLOAD_SIZE;
    cfg->pipeline = DEFAULT_PIPELINE;
    cfg->duration_s = DEFAULT_DURATION_S;
    cfg->flush_interval_ms = DEFAULT_FLUSH_INTERVAL_MS;
    snprintf(cfg->redis_endpoint, sizeof(cfg->redis_endpoint), "%s", DEFAULT_REDIS_ENDPOINT);

    for (;;) {
        int c = getopt_long(argc, argv, "h", long_opts, NULL);

        if (c == -1)
            break;

        switch (c) {
        case OPT_PAYLOAD_SIZE:
            cfg->payload_size = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case OPT_PIPELINE:
            cfg->pipeline = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case OPT_DURATION_S:
            cfg->duration_s = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case OPT_REDIS:
            snprintf(cfg->redis_endpoint, sizeof(cfg->redis_endpoint), "%s", optarg);
            break;
        case OPT_FLUSH_INTERVAL_MS:
            cfg->flush_interval_ms = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case OPT_HELP:
        case 'h':
            print_usage(argv[0]);
            exit(0);
        default:
            print_usage(argv[0]);
            return -1;
        }
    }

    if (cfg->payload_size == 0 || cfg->payload_size > CLOUDFLOW_EVENT_MAX_SIZE) {
        fprintf(stderr, "bench_xadd: --payload-size must be in [1, %u], clamping\n",
                CLOUDFLOW_EVENT_MAX_SIZE);
        if (cfg->payload_size == 0)
            cfg->payload_size = 1;
        else
            cfg->payload_size = CLOUDFLOW_EVENT_MAX_SIZE;
    }

    if (cfg->duration_s == 0) {
        fprintf(stderr, "bench_xadd: --duration-s must be >= 1\n");
        return -1;
    }

    return 0;
}

/* ---- main ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    bench_config_t cfg;
    cf_queue_t queue;
    cf_redis_stats_t stats;
    cf_redis_producer_config_t producer_cfg;
    const char *endpoints[1];
    generator_ctx_t gen_ctx;
    pthread_t gen_thread;
    size_t queue_capacity;
    int64_t t_start, t_stop_requested, t_end;
    double elapsed_s;
    unsigned long xadd_total, xadd_errors_total, reconnects, events_lost;
    double events_per_sec, mb_per_sec, avg_latency_us;
    int64_t remaining_s;

    if (parse_args(argc, argv, &cfg) != 0)
        return 2;

    cf_stop_install_signal_handlers();

    endpoints[0] = cfg.redis_endpoint;

    queue_capacity = (size_t)cfg.pipeline * QUEUE_CAPACITY_MULT;
    if (queue_capacity < QUEUE_CAPACITY_MIN)
        queue_capacity = QUEUE_CAPACITY_MIN;
    if (queue_capacity > QUEUE_CAPACITY_MAX)
        queue_capacity = QUEUE_CAPACITY_MAX;

    if (cf_queue_init(&queue, queue_capacity, sizeof(cf_event_item_t)) != 0) {
        fprintf(stderr, "bench_xadd: cf_queue_init failed (capacity=%zu)\n", queue_capacity);
        return 1;
    }

    memset(&stats, 0, sizeof(stats));

    trim_streams(cfg.redis_endpoint);

    memset(&producer_cfg, 0, sizeof(producer_cfg));
    producer_cfg.endpoints = endpoints;
    producer_cfg.endpoint_count = 1;
    producer_cfg.maxlen_approx = 0;
    producer_cfg.pipeline_max = cfg.pipeline;
    producer_cfg.flush_interval_ms = cfg.flush_interval_ms;
    producer_cfg.in = &queue;
    producer_cfg.stats = &stats;

    fprintf(stderr,
            "bench_xadd: starting run payload_size=%u pipeline=%u duration_s=%u "
            "flush_interval_ms=%u redis=%s queue_capacity=%zu\n",
            cfg.payload_size, cfg.pipeline, cfg.duration_s, cfg.flush_interval_ms,
            cfg.redis_endpoint, queue_capacity);

    if (cf_redis_producer_start(&producer_cfg) != 0) {
        fprintf(stderr, "bench_xadd: cf_redis_producer_start failed (invalid config?)\n");
        cf_queue_destroy(&queue);
        return 1;
    }

    gen_ctx.queue = &queue;
    gen_ctx.payload_size = cfg.payload_size;
    atomic_init(&gen_ctx.stop, 0);

    t_start = cf_now_mono_nano();

    if (pthread_create(&gen_thread, NULL, generator_thread_main, &gen_ctx) != 0) {
        fprintf(stderr, "bench_xadd: failed to start generator thread\n");
        atomic_store(&gen_ctx.stop, 1);
        cf_redis_producer_stop();
        cf_queue_destroy(&queue);
        return 1;
    }

    /* Run for --duration-s, polling in short slices (no fixed long sleep)
     * so a SIGINT/SIGTERM caught by cf_stop_install_signal_handlers() can
     * cut the run short cleanly instead of blocking until the deadline. */
    remaining_s = (int64_t)cfg.duration_s;
    while (remaining_s > 0 && !cf_stop_notified()) {
        struct timespec ts = {.tv_sec = 1, .tv_nsec = 0};

        nanosleep(&ts, NULL);
        remaining_s--;
    }

    t_stop_requested = cf_now_mono_nano();

    atomic_store(&gen_ctx.stop, 1);
    pthread_join(gen_thread, NULL);

    /* cf_redis_producer_stop() drains whatever is left in the queue and
     * flushes the in-flight pipeline (up to its own 5s deadline) before
     * returning -- it does not need (and this binary never sets)
     * cf_stop_notify()'s process-wide flag. */
    cf_redis_producer_stop();

    t_end = cf_now_mono_nano();

    cf_queue_destroy(&queue);

    xadd_total = CF_ATOMIC_READ(stats.xadd_total);
    xadd_errors_total = CF_ATOMIC_READ(stats.xadd_errors_total);
    reconnects = CF_ATOMIC_READ(stats.redis_reconnects_total);
    events_lost = CF_ATOMIC_READ(stats.events_lost_total);

    elapsed_s = (double)(t_end - t_start) / 1e9;
    if (elapsed_s <= 0.0)
        elapsed_s = (double)cfg.duration_s;

    events_per_sec = (double)xadd_total / elapsed_s;
    mb_per_sec = ((double)xadd_total * (double)cfg.payload_size) / (1024.0 * 1024.0) / elapsed_s;
    avg_latency_us = xadd_total > 0
                         ? ((double)CF_ATOMIC_READ(stats.xadd_latency_ns_total) / (double)xadd_total) / 1000.0
                         : 0.0;

    fprintf(stderr, "bench_xadd: generation window %.3fs, drain took %.3fs more\n",
            (double)(t_stop_requested - t_start) / 1e9, (double)(t_end - t_stop_requested) / 1e9);

    printf("payload_size=%u pipeline=%u duration_s=%u flush_interval_ms=%u "
           "elapsed_s=%.3f events=%lu events_per_sec=%.1f mb_per_sec=%.3f "
           "avg_xadd_latency_us=%.3f xadd_errors_total=%lu reconnects=%lu events_lost_total=%lu\n",
           cfg.payload_size, cfg.pipeline, cfg.duration_s, cfg.flush_interval_ms, elapsed_s, xadd_total,
           events_per_sec, mb_per_sec, avg_latency_us, xadd_errors_total, reconnects, events_lost);

    return events_lost != 0 ? 1 : 0;
}
