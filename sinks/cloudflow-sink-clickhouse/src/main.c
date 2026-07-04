/* cloudflow-sink-clickhouse: Redis Streams -> ClickHouse columnar sink (C).
 *
 * Thin wiring over the shared sink spine (libs/cloudflow-sink-core): this
 * process parses the CLI + ClickHouse config, supplies the CloudFlowEvent ->
 * JSONEachRow row transform (src/row_transform.c) and a pluggable ClickHouse
 * delivery client (src/ch_client.c), then calls cf_sink_run. The consume ->
 * transform -> batch -> deliver -> ack loop, the dead-letter path and the stats
 * line all live in the spine and are reused verbatim; only the transform and
 * the delivery client are ClickHouse-specific (docs/clickhouse-sink.md).
 *
 * The ClickHouse sink is a consumer group (`sink-clickhouse`) on the same wire
 * streams as the Splunk sinks, writing rows into `<database>.<table>` for
 * columnar/analytical queries. Its consumer group, streams and dead-letter
 * stream come from the YAML config (configs/examples/clickhouse-sink.yaml wires
 * the canonical values fixed in src/config.h).
 *
 * CLI: -c/--config <path> (required), --stdout (print the JSONEachRow rows
 * instead of inserting -- no client / credentials needed), --once (drain what is
 * pending then exit), --version. SIGTERM/SIGINT trigger a flush-once-then-exit
 * via the spine's stop flag. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

#include "cf_log.h"
#include "cf_sink_delivery.h"
#include "cf_sink_run.h"
#include "cf_sink_stats.h"
#include "ch_client.h"
#include "config.h"
#include "row_transform.h"

#ifndef CF_SINK_CLICKHOUSE_VERSION
#define CF_SINK_CLICKHOUSE_VERSION "0.1.0"
#endif

static void usage(FILE *out, const char *prog)
{
    fprintf(out,
            "usage: %s -c <config.yaml> [--stdout] [--once] [--version]\n"
            "  -c, --config PATH   sink YAML config (required)\n"
            "      --stdout        print JSONEachRow rows instead of inserting\n"
            "      --once          process what is currently pending, then exit\n"
            "      --version       print version and exit\n",
            prog);
}

int main(int argc, char **argv)
{
    const char *config_path = NULL;
    int stdout_mode = 0;
    int once = 0;
    int i;
    cf_config_t cfg;
    char errbuf[512];
    cf_stats_t stats;
    cf_sink_run_options_t opt;
    ch_client_t *client = NULL;
    cf_sink_delivery_t delivery;
    int rc;

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
            printf("cloudflow-sink-clickhouse %s\n", CF_SINK_CLICKHOUSE_VERSION);
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

    cf_log_init(cfg.base.service.name);
    cf_stats_init(&stats);

    memset(&opt, 0, sizeof(opt));
    opt.config = &cfg.base;
    opt.stats = &stats;
    opt.transform = cf_row_transform;
    opt.transform_user = NULL;
    opt.stdout_mode = stdout_mode;
    opt.once = once;
    opt.stdout_stream = stdout;

    /* --stdout "delivers" by printing rows, so no client / credentials are
     * needed. Otherwise build the ClickHouse delivery client (owning the curl
     * globals, since the spine only manages them when it builds the HEC client
     * itself) and hand it to the spine as a pluggable delivery. */
    if (!stdout_mode) {
        ch_client_config_t chc;
        memset(&chc, 0, sizeof(chc));
        chc.url = cfg.url;
        chc.database = cfg.database;
        chc.table = cfg.table;
        chc.user_env = cfg.user_env;
        chc.password_env = cfg.password_env;
        chc.request_timeout_ms = cfg.request_timeout_ms;
        chc.tls_verify = cfg.tls_verify;

        curl_global_init(CURL_GLOBAL_DEFAULT);
        client = ch_client_new(&chc, &stats, errbuf, sizeof(errbuf));
        if (!client) {
            cf_log(CF_LOG_ERROR, "ClickHouse client init failed", "error", errbuf, NULL);
            curl_global_cleanup();
            cf_config_free(&cfg);
            return 1;
        }
        delivery = cf_ch_client_as_delivery(client);
        opt.delivery = &delivery;
    }

    rc = cf_sink_run(&opt);

    if (client) {
        ch_client_free(client);
        curl_global_cleanup();
    }
    cf_config_free(&cfg);
    return rc;
}
