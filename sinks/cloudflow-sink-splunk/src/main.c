/* WP-17 -- cloudflow-sink-splunk: Redis Streams -> Splunk HEC sink (C).
 *
 * CLI: -c/--config <path> (required), --stdout (print HEC JSON instead of
 * POSTing), --once (drain what is pending then exit), --version. SIGTERM/
 * SIGINT trigger a flush-once-then-exit via cf_sync's stop flag. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include <hiredis/hiredis.h>

#include "cf_log.h"
#include "cf_sync.h"
#include "config.h"
#include "consumer.h"
#include "hec.h"
#include "stats.h"

#ifndef CF_SINK_SPLUNK_VERSION
#define CF_SINK_SPLUNK_VERSION "0.1.0"
#endif

static void usage(FILE *out, const char *prog)
{
    fprintf(out,
            "usage: %s -c <config.yaml> [--stdout] [--once] [--version]\n"
            "  -c, --config PATH   sink YAML config (required)\n"
            "      --stdout        print HEC-shaped JSON lines instead of POSTing\n"
            "      --once          process what is currently pending, then exit\n"
            "      --version       print version and exit\n",
            prog);
}

/* Connect to the first reachable endpoint (D3). Returns NULL on total failure. */
static redisContext *connect_redis(const cf_redis_config_t *rc)
{
    size_t i;
    for (i = 0; i < rc->endpoint_count; i++) {
        const char *ep = rc->endpoints[i];
        const char *colon = strrchr(ep, ':');
        char host[256];
        int port;
        redisContext *ctx;
        size_t hlen;

        if (!colon || colon == ep)
            continue;
        hlen = (size_t)(colon - ep);
        if (hlen >= sizeof(host))
            continue;
        memcpy(host, ep, hlen);
        host[hlen] = '\0';
        port = atoi(colon + 1);
        if (port <= 0 || port > 65535)
            continue;

        ctx = redisConnect(host, port);
        if (ctx && !ctx->err)
            return ctx;
        if (ctx)
            redisFree(ctx);
    }
    return NULL;
}

int main(int argc, char **argv)
{
    const char *config_path = NULL;
    int stdout_mode = 0;
    int once = 0;
    int i;
    cf_config_t cfg;
    char errbuf[512];
    redisContext *ctx = NULL;
    cf_stats_t stats;
    cf_consumer_t consumer;
    cf_hec_client_t *hec = NULL;
    int rc = 0;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) {
            if (i + 1 >= argc) {
                usage(stderr, argv[0]);
                return 2;
            }
            config_path = argv[++i];
        } else if (strcmp(argv[i], "--stdout") == 0) {
            stdout_mode = 1;
        } else if (strcmp(argv[i], "--once") == 0) {
            once = 1;
        } else if (strcmp(argv[i], "--version") == 0) {
            printf("cloudflow-sink-splunk %s\n", CF_SINK_SPLUNK_VERSION);
            return 0;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(stdout, argv[0]);
            return 0;
        } else {
            fprintf(stderr, "unknown argument: %s\n", argv[i]);
            usage(stderr, argv[0]);
            return 2;
        }
    }

    if (!config_path) {
        usage(stderr, argv[0]);
        return 2;
    }

    if (cf_config_load(config_path, &cfg, errbuf, sizeof(errbuf)) != 0) {
        cf_log(CF_LOG_ERROR, "config load failed", "error", errbuf, NULL);
        return 1;
    }

    cf_log_init(cfg.service.name);
    cf_stats_init(&stats);

    cf_log(CF_LOG_INFO, "starting", "consumer_name", cfg.service.consumer_name, "stdout_mode",
           stdout_mode ? "true" : "false", "once", once ? "true" : "false", NULL);

    ctx = connect_redis(&cfg.redis);
    if (!ctx) {
        cf_log(CF_LOG_ERROR, "could not connect to any redis endpoint", NULL);
        cf_config_free(&cfg);
        return 1;
    }

    if (!stdout_mode) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        hec = cf_hec_client_new(&cfg.splunk, &stats, errbuf, sizeof(errbuf));
        if (!hec) {
            cf_log(CF_LOG_ERROR, "HEC client init failed", "error", errbuf, NULL);
            redisFree(ctx);
            cf_config_free(&cfg);
            curl_global_cleanup();
            return 1;
        }
    }

    if (cf_consumer_init(&consumer, ctx, &cfg, &stats) != 0) {
        cf_log(CF_LOG_ERROR, "consumer init failed", NULL);
        rc = 1;
        goto cleanup;
    }
    if (stdout_mode)
        cf_consumer_set_stdout(&consumer, stdout);
    else
        cf_consumer_set_hec(&consumer, hec);

    cf_stop_install_signal_handlers();

    if (once) {
        cf_consumer_run_once(&consumer);
        cf_stats_emit(&stats);
    } else {
        cf_consumer_run_forever(&consumer);
    }

    cf_consumer_free(&consumer);
    cf_log(CF_LOG_INFO, "exiting", NULL);

cleanup:
    if (hec)
        cf_hec_client_free(hec);
    if (ctx)
        redisFree(ctx);
    if (!stdout_mode)
        curl_global_cleanup();
    cf_config_free(&cfg);
    return rc;
}
