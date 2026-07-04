#ifndef CF_SINK_CLICKHOUSE_CONFIG_H
#define CF_SINK_CLICKHOUSE_CONFIG_H

/* cloudflow-sink-clickhouse -- ClickHouse-sink configuration, layered on the
 * shared base config struct (libs/cloudflow-sink-core, cf_sink_config_t).
 *
 * The ClickHouse sink is NOT a Splunk sink, so it does not use the base
 * `splunk:` HEC section; instead this module parses `service`, `redis` and a
 * `clickhouse:` section itself, filling the embedded cf_sink_config_t `base`
 * (which the spine's run loop + consumer read for service identity, the Redis
 * consumer-group topology and the batch/flush tuning) plus the ClickHouse
 * connection parameters. The base struct is embedded so cf_sink_config_free
 * still releases the service/redis heap and the spine sees an ordinary
 * cf_sink_config_t.
 *
 * Same secret rule as the Splunk sinks (decision D6): the HTTP Basic
 * credentials come ONLY from the environment variables NAMED by
 * `clickhouse.user_env` / `clickhouse.password_env`; a literal secret in YAML,
 * or an env-var name that does not look like one, is a fatal startup error. */

#include <stddef.h>

#include "cf_sink_config.h"

/* ClickHouse sink identity (docs/clickhouse-sink.md, docs/architecture.md).
 * The canonical, documented values wired into the base config's YAML
 * (consumer_group / deadletter_stream); fixing them here keeps the contract in
 * one place, exactly like the Splunk sinks do. */
#define CF_SINK_CLICKHOUSE_CONSUMER_GROUP "sink-clickhouse"
#define CF_SINK_CLICKHOUSE_DEADLETTER_STREAM "cloudflow:v1:deadletter:sink-clickhouse"
#define CF_SINK_CLICKHOUSE_DEFAULT_DATABASE "cloudflow"
#define CF_SINK_CLICKHOUSE_DEFAULT_TABLE "events"

typedef struct {
    cf_sink_config_t base; /* service, redis, and (batch/flush only) hec */

    char *url;          /* ClickHouse HTTP base URL (required) */
    char *database;     /* target database (default: cloudflow) */
    char *table;        /* target table (default: events) */
    char *user_env;     /* env var NAME for HTTP Basic user; "" => no auth */
    char *password_env; /* env var NAME for HTTP Basic password; "" => empty */
    int tls_verify;     /* default 1 */
    int request_timeout_ms;
} cf_config_t;

/* Load and validate the config at `path`. On success returns 0 and fills `out`
 * (owns heap memory; release with cf_config_free). On failure returns -1 and
 * writes a human-readable message into `errbuf` (never a secret). */
int cf_config_load(const char *path, cf_config_t *out, char *errbuf, size_t errcap);

/* Parse an in-memory YAML document (used by tests). Same contract. */
int cf_config_parse(const char *yaml_text, size_t yaml_len, cf_config_t *out, char *errbuf,
                    size_t errcap);

void cf_config_free(cf_config_t *cfg);

#endif
