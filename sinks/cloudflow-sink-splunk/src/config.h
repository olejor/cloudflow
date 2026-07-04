#ifndef CF_SINK_SPLUNK_CONFIG_H
#define CF_SINK_SPLUNK_CONFIG_H

/* cloudflow-sink-splunk -- event-sink configuration, layered on the shared
 * base config (libs/cloudflow-sink-core, cf_sink_config).
 *
 * The base config (service, redis topology + dead-letter stream, HEC
 * url/path/token-env/index/batch/flush/timeout/tls) is parsed by
 * cf_sink_config_*. This adds the event-sink-specific keys under `splunk`:
 * the `sourcetypes` map and `include_raw_payload`, used only by the event
 * transform (docs/splunk-output.md, "Canonical HEC mapping").
 */

#include <stddef.h>

#include "cf_sink_config.h"

/* Event sink identity (docs/splunk-output.md, docs/architecture.md). */
#define CF_SINK_SPLUNK_CONSUMER_GROUP "sink-splunk"
#define CF_SINK_SPLUNK_DEADLETTER_STREAM "cloudflow:v1:deadletter:sink-splunk"
#define CF_SINK_SPLUNK_HEC_PATH "/services/collector/event"

typedef struct {
    cf_sink_config_t base;   /* service, redis, hec */
    char **st_keys;          /* sourcetypes map keys (source_type) */
    char **st_vals;          /* sourcetypes map values (Splunk sourcetype) */
    size_t st_count;
    int include_raw_payload; /* default 0 */
} cf_config_t;

/* Load and validate the config at `path`. On success returns 0 and fills
 * `out` (owns heap memory; release with cf_config_free). On failure returns
 * -1 and writes a human-readable message into `errbuf` (never a secret). */
int cf_config_load(const char *path, cf_config_t *out, char *errbuf, size_t errcap);

/* Parse an in-memory YAML document (used by tests). Same contract. */
int cf_config_parse(const char *yaml_text, size_t yaml_len, cf_config_t *out, char *errbuf,
                    size_t errcap);

void cf_config_free(cf_config_t *cfg);

/* Resolve the configured sourcetype for `source_type`; falls back to
 * "cloudflow:<source_type>" written into `buf`. Returns a pointer valid
 * until the next call or config free (either into the config or into buf). */
const char *cf_splunk_sourcetype_for(const cf_config_t *cfg, const char *source_type, char *buf,
                                     size_t cap);

#endif
