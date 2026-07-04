/* cloudflow-sink-splunk-metrics: Redis Streams -> Splunk HEC metrics sink (C).
 *
 * Thin wiring over the shared sink spine (libs/cloudflow-sink-core): this
 * process only parses the CLI + metrics config and supplies the
 * event->metric-point transform (src/metrics_transform.c). The consume ->
 * transform -> batch -> deliver -> ack loop, the HEC client, the dead-letter
 * path and the stats line all live in the spine and are reused verbatim from
 * the event sink -- only the transform differs (docs/splunk-metrics.md).
 *
 * The metrics sink is a second consumer group (`sink-splunk-metrics`) on the
 * same wire streams as the event sink, delivering metric points to Splunk's
 * metrics index via HEC `/services/collector`. Its consumer group, HEC path,
 * streams and dead-letter stream come from the YAML config
 * (configs/examples/splunk-metrics.yaml wires the canonical values fixed in
 * src/config.h).
 *
 * CLI: -c/--config <path> (required), --stdout (print metric-point JSON instead
 * of POSTing), --once (drain what is pending then exit), --version. SIGTERM/
 * SIGINT trigger a flush-once-then-exit via the spine's stop flag. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cf_log.h"
#include "cf_sink_run.h"
#include "cf_sink_stats.h"
#include "config.h"
#include "metrics_transform.h"

#ifndef CF_SINK_SPLUNK_METRICS_VERSION
#define CF_SINK_SPLUNK_METRICS_VERSION "0.1.0"
#endif

static void usage(FILE *out, const char *prog)
{
    fprintf(out,
            "usage: %s -c <config.yaml> [--stdout] [--once] [--version]\n"
            "  -c, --config PATH   sink YAML config (required)\n"
            "      --stdout        print metric-point JSON lines instead of POSTing\n"
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
            printf("cloudflow-sink-splunk-metrics %s\n", CF_SINK_SPLUNK_METRICS_VERSION);
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
    opt.transform = cf_metrics_transform;
    opt.transform_user = &cfg;
    opt.stdout_mode = stdout_mode;
    opt.once = once;
    opt.stdout_stream = stdout;

    rc = cf_sink_run(&opt);

    cf_config_free(&cfg);
    return rc;
}
