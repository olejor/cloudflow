#include "cf_sink_run.h"

#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include <hiredis/hiredis.h>

#include "cf_log.h"
#include "cf_sync.h"

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

int cf_sink_run(const cf_sink_run_options_t *opt)
{
    const cf_sink_config_t *cfg = opt->config;
    redisContext *ctx = NULL;
    cf_hec_client_t *hec = NULL;          /* built here only when no delivery is supplied */
    cf_sink_delivery_t hec_delivery;      /* wraps `hec` when we build it */
    const cf_sink_delivery_t *delivery = NULL;
    int built_hec = 0;                    /* owns `hec` + curl_global lifecycle */
    cf_consumer_t consumer;
    char errbuf[512];
    int rc = 0;

    cf_log(CF_LOG_INFO, "starting", "consumer_name", cfg->service.consumer_name, "stdout_mode",
           opt->stdout_mode ? "true" : "false", "once", opt->once ? "true" : "false", NULL);

    ctx = connect_redis(&cfg->redis);
    if (!ctx) {
        cf_log(CF_LOG_ERROR, "could not connect to any redis endpoint", NULL);
        return 1;
    }

    if (!opt->stdout_mode) {
        if (opt->delivery) {
            /* Caller supplied a pluggable delivery client; use it verbatim and
             * leave ownership (and any transport globals) to the caller. */
            delivery = opt->delivery;
        } else {
            /* Default: build the HEC client from config exactly as before and
             * drive it through the same delivery interface. */
            curl_global_init(CURL_GLOBAL_DEFAULT);
            hec = cf_hec_client_new(&cfg->hec, opt->stats, errbuf, sizeof(errbuf));
            if (!hec) {
                cf_log(CF_LOG_ERROR, "HEC client init failed", "error", errbuf, NULL);
                redisFree(ctx);
                curl_global_cleanup();
                return 1;
            }
            hec_delivery = cf_hec_client_as_delivery(hec);
            delivery = &hec_delivery;
            built_hec = 1;
        }
    }

    if (cf_consumer_init(&consumer, ctx, cfg, opt->stats) != 0) {
        cf_log(CF_LOG_ERROR, "consumer init failed", NULL);
        rc = 1;
        goto cleanup;
    }
    cf_consumer_set_transform(&consumer, opt->transform, opt->transform_user);
    if (opt->stdout_mode)
        cf_consumer_set_stdout(&consumer, opt->stdout_stream);
    else
        cf_consumer_set_delivery(&consumer, delivery);
    if (opt->min_idle_ms > 0)
        cf_consumer_set_min_idle_ms(&consumer, opt->min_idle_ms);

    cf_stop_install_signal_handlers();

    if (opt->once) {
        cf_consumer_run_once(&consumer);
        cf_stats_emit(opt->stats);
    } else {
        cf_consumer_run_forever(&consumer);
    }

    cf_consumer_free(&consumer);
    cf_log(CF_LOG_INFO, "exiting", NULL);

cleanup:
    if (built_hec)
        cf_hec_client_free(hec);
    if (ctx)
        redisFree(ctx);
    if (built_hec)
        curl_global_cleanup();
    return rc;
}
