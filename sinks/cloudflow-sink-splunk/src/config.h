#ifndef CF_SINK_SPLUNK_CONFIG_H
#define CF_SINK_SPLUNK_CONFIG_H

/* WP-17 -- Splunk sink YAML configuration (libyaml).
 *
 * Same schema and env rules as WP-12 (docs/splunk-output.md,
 * decision D6): endpoints and topology come from YAML; the HEC token comes
 * only from the environment variable named by splunk.hec_token_env. A
 * literal token key in YAML, or a splunk.hec_token_env value that does not
 * look like an environment-variable name, is a fatal startup error.
 */

#include <stddef.h>

typedef struct {
    char *name;
    char *consumer_name;
} cf_service_config_t;

typedef struct {
    char **endpoints;
    size_t endpoint_count;
    char **streams;
    size_t stream_count;
    char *consumer_group;
    int read_count;
    int block_ms;
} cf_redis_config_t;

typedef struct {
    char *hec_url;
    char *hec_token_env;
    char *index; /* "" when unset; omitted from HEC events when empty */
    char **st_keys;
    char **st_vals;
    size_t st_count;
    int batch_size;
    int flush_interval_ms;
    int request_timeout_ms;
    int tls_verify;          /* default 1 */
    int include_raw_payload; /* default 0 */
} cf_splunk_config_t;

typedef struct {
    cf_service_config_t service;
    cf_redis_config_t redis;
    cf_splunk_config_t splunk;
} cf_config_t;

/* Load and validate the config at `path`. On success returns 0 and fills
 * `out` (owns heap memory; release with cf_config_free). On failure returns
 * -1 and writes a human-readable message into `errbuf` (never containing a
 * secret). */
int cf_config_load(const char *path, cf_config_t *out, char *errbuf, size_t errcap);

/* Parse an in-memory YAML document (used by tests). Same contract as
 * cf_config_load. */
int cf_config_parse(const char *yaml_text, size_t yaml_len, cf_config_t *out,
                    char *errbuf, size_t errcap);

void cf_config_free(cf_config_t *cfg);

/* Resolve the configured sourcetype for `source_type`; falls back to
 * "cloudflow:<source_type>" written into `buf`. Returns a pointer valid
 * until the next call or config free (either into the config or into buf). */
const char *cf_splunk_sourcetype_for(const cf_splunk_config_t *s,
                                     const char *source_type,
                                     char *buf, size_t cap);

/* Resolve the HEC token from getenv(hec_token_env). Returns NULL if the env
 * var is unset or empty. Never reads a token from YAML. */
const char *cf_splunk_resolve_token(const cf_splunk_config_t *s);

#endif
