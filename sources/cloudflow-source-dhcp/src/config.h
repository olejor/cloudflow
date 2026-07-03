#ifndef CF_SOURCE_DHCP_CONFIG_H
#define CF_SOURCE_DHCP_CONFIG_H

/* WP-11: YAML config loading for the cloudflow-source-dhcp application, per
 * docs/design/03-source-dhcp.md's WP-11 section and D6
 * (docs/design/00-overview.md). Loads the schema documented by
 * configs/examples/dhcp-source.yaml with libyaml, doing a flat mapping walk
 * (service/capture/queues/redis/stats sections, each a simple key -> scalar
 * or key -> sequence-of-scalars mapping -- no anchors/aliases/multi-doc
 * support needed for this schema). Unknown keys (at any level) are logged
 * via cf_log(CF_LOG_WARN, ...) and ignored, not fatal. Missing keys default
 * to the values already committed in configs/examples/dhcp-source.yaml
 * (see the CF_CONFIG_DEFAULT_* constants in config.c), except
 * `stats.interval_s` (not present in that file) which defaults to 10 and
 * `stats.reset_on_report` which defaults to false.
 *
 * capture.method accepts only "rxring" -- any other value is a fatal parse
 * error (cf_config_load() logs via cf_log(CF_LOG_ERROR, ...) and returns
 * NULL). capture.filter is informational only in v0.1 (D7): if present, a
 * warning is logged at load time noting the builtin BPF filter is used
 * regardless of this string's contents.
 *
 * redis.stream_dhcpv4/redis.stream_dhcpv6 are likewise informational: the
 * WP-09 producer (libs/cloudflow-redis) hardcodes stream names via
 * cf_stream_name() and has no per-instance override in its config struct
 * (see cf_redis_producer.h), so these two YAML keys are parsed, stored, and
 * compared against cf_stream_name(CF_STREAM_DHCPV4)/CF_STREAM_DHCPV6) purely
 * so a mismatch can be logged as a warning -- they do not change producer
 * behavior.
 */

#include <stddef.h>
#include <stdint.h>

#include "queue_policy.h"

typedef struct {
    char *service_name;
    char *source_host; /* "" or NULL => main.c falls back to gethostname() */

    char *capture_interface;
    char *capture_method; /* always "rxring" after a successful load */
    uint32_t capture_snaplen;
    char *capture_filter; /* informational only, D7 */

    uint32_t rx_to_formatter_capacity;
    uint32_t formatter_to_redis_capacity;
    cf_queue_full_policy_t queues_on_full;

    char **redis_endpoints; /* heap array of heap "host:port" strings */
    size_t redis_endpoint_count;
    char *redis_stream_dhcpv4; /* informational, see header comment above */
    char *redis_stream_dhcpv6; /* informational, see header comment above */
    long long redis_maxlen_approx;
    uint32_t redis_xadd_batch_size;       /* -> cf_redis_producer_config_t.pipeline_max */
    uint32_t redis_xadd_flush_interval_ms;

    uint32_t stats_interval_s;
    int stats_reset_on_report; /* 0/1 */
} cf_source_config_t;

/* Loads and validates a cf_source_config_t from the YAML file at `path`,
 * then applies environment overrides on top (in this order):
 *
 *   CF_REDIS_ENDPOINTS  comma-separated "host:port" list; replaces the
 *                       entire redis.endpoints list.
 *   CF_INTERFACE        replaces capture.interface.
 *   CF_SOURCE_HOST      replaces service.source_host.
 *
 * Returns a heap-allocated, fully-owned config (every pointer field is a
 * private heap allocation -- free with cf_config_free()) on success. Returns
 * NULL on any fatal error (file open/read failure, malformed YAML, root
 * node not a mapping, invalid capture.method), having already logged a
 * clear cf_log(CF_LOG_ERROR, ...) line describing what went wrong; the
 * caller (main.c) is responsible for exiting with a non-zero status. */
cf_source_config_t *cf_config_load(const char *path);

/* Frees a config returned by cf_config_load(). NULL-safe. */
void cf_config_free(cf_source_config_t *cfg);

#endif
