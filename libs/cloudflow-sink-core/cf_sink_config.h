#ifndef CF_SINK_CORE_CONFIG_H
#define CF_SINK_CORE_CONFIG_H

/* Shared sink spine (A1) -- base YAML configuration common to every Splunk
 * sink (libyaml).
 *
 * This is the generic half of the sink config: the service identity, the
 * Redis consumer-group topology (endpoints, input streams, group name,
 * read/block tuning, dead-letter stream), and the HEC delivery parameters
 * (url + endpoint path, token env-var name, index, batch/flush/timeout,
 * TLS verify). Sink-specific keys (e.g. the event sink's `sourcetypes` map
 * and `include_raw_payload`) are layered on top by the sink itself and are
 * NOT parsed here -- unknown keys are ignored.
 *
 * Same env rules as before (decision D6, docs/splunk-output.md): endpoints
 * and topology come from YAML; the HEC token comes only from the environment
 * variable named by splunk.hec_token_env. A literal token key in YAML, or a
 * splunk.hec_token_env value that does not look like an environment-variable
 * name, is a fatal startup error.
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
    char *deadletter_stream; /* dead-letter stream name (config, per sink) */
} cf_redis_config_t;

typedef struct {
    char *hec_url;       /* HEC base URL (may already include the endpoint path) */
    char *hec_path;      /* endpoint path appended to hec_url; "" when unused */
    char *hec_token_env; /* env var name holding the token (D6); never a literal */
    char *index;         /* "" when unset; omitted from HEC events when empty */
    int batch_size;
    int flush_interval_ms;
    int request_timeout_ms;
    int tls_verify; /* default 1 */
} cf_hec_config_t;

typedef struct {
    cf_service_config_t service;
    cf_redis_config_t redis;
    cf_hec_config_t hec;
} cf_sink_config_t;

/* Load and validate the base config at `path`. On success returns 0 and
 * fills `out` (owns heap memory; release with cf_sink_config_free). On
 * failure returns -1 and writes a human-readable message into `errbuf`
 * (never containing a secret). Sink-specific keys are ignored here. */
int cf_sink_config_load(const char *path, cf_sink_config_t *out, char *errbuf, size_t errcap);

/* Parse an in-memory YAML document (used by tests). Same contract as
 * cf_sink_config_load. */
int cf_sink_config_parse(const char *yaml_text, size_t yaml_len, cf_sink_config_t *out,
                         char *errbuf, size_t errcap);

void cf_sink_config_free(cf_sink_config_t *cfg);

/* Resolve the HEC token from getenv(hec_token_env). Returns NULL if the env
 * var is unset or empty. Never reads a token from YAML. */
const char *cf_sink_resolve_token(const cf_hec_config_t *h);

#endif
