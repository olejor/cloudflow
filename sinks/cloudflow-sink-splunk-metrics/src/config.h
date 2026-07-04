#ifndef CF_SINK_SPLUNK_METRICS_CONFIG_H
#define CF_SINK_SPLUNK_METRICS_CONFIG_H

/* cloudflow-sink-splunk-metrics -- metrics-sink configuration, layered on the
 * shared base config (libs/cloudflow-sink-core, cf_sink_config).
 *
 * The base config (service, redis topology + dead-letter stream, HEC
 * url/path/token-env/index/batch/flush/timeout/tls) is parsed by
 * cf_sink_config_*. This adds the metrics-sink-specific keys under `splunk`:
 * the `metrics_index` the metric points carry, an `enabled_metrics` allowlist,
 * and per-metric cardinality controls (`dimensions`) that select which
 * (optionally high-cardinality) dimension keys are emitted -- see
 * docs/splunk-metrics.md, "Metric mapping" and "Configuration". Only used by
 * the metrics transform (src/metrics_transform.c); the HEC token stays env-only
 * (D6), supplied by the base.
 */

#include <stddef.h>

#include "cf_sink_config.h"

/* Metrics sink identity (docs/splunk-metrics.md, docs/architecture.md).
 * As with the event sink these are the canonical, documented values the
 * example config + integration test wire into the base config's YAML
 * (consumer_group / hec_path / deadletter_stream); the spine reads them from
 * the parsed config, so keeping them here fixes the contract in one place. */
#define CF_SINK_SPLUNK_METRICS_CONSUMER_GROUP "sink-splunk-metrics"
#define CF_SINK_SPLUNK_METRICS_DEADLETTER_STREAM "cloudflow:v1:deadletter:sink-splunk-metrics"
#define CF_SINK_SPLUNK_METRICS_HEC_PATH "/services/collector"

/* Canonical metric names (the contract; docs/splunk-metrics.md). */
#define CF_METRIC_DNS_RTT_SECONDS "dns.rtt_seconds"
#define CF_METRIC_DNS_TRANSACTIONS_TOTAL "dns.transactions_total"
#define CF_METRIC_DNS_UNANSWERED_TOTAL "dns.unanswered_total"
#define CF_METRIC_DNS_UNMATCHED_TOTAL "dns.unmatched_total"
#define CF_METRIC_DHCP_EVENTS_TOTAL "dhcp.events_total"

typedef struct {
    cf_sink_config_t base; /* service, redis, hec */

    /* Splunk metrics index the metric points carry (metric-point `index`
     * field). "" => omitted from the metric point, like the event sink's
     * empty splunk.index. */
    char *metrics_index;

    /* Allowlist of metric names that may be emitted. NULL / count 0 means
     * "all metrics enabled" (no restriction). */
    char **enabled_metrics;
    size_t enabled_count;

    /* Per-metric cardinality controls (docs/splunk-metrics.md,
     * "Configuration"): which optional dimensions to include. */
    int dim_dns_server_ip;   /* include cf_server_ip on DNS metrics; default 1 */
    int dim_dns_qtype;       /* include cf_qtype on DNS metrics;     default 1 */
    int dim_dhcp_client_key; /* include cf_client_key on DHCP;       default 0 */
} cf_config_t;

/* Load and validate the config at `path`. On success returns 0 and fills
 * `out` (owns heap memory; release with cf_config_free). On failure returns
 * -1 and writes a human-readable message into `errbuf` (never a secret). */
int cf_config_load(const char *path, cf_config_t *out, char *errbuf, size_t errcap);

/* Parse an in-memory YAML document (used by tests). Same contract. */
int cf_config_parse(const char *yaml_text, size_t yaml_len, cf_config_t *out, char *errbuf,
                    size_t errcap);

void cf_config_free(cf_config_t *cfg);

/* True if `metric_name` is allowed to be emitted under this config (i.e. the
 * allowlist is empty, or it lists that name). */
int cf_metrics_enabled(const cf_config_t *cfg, const char *metric_name);

#endif
