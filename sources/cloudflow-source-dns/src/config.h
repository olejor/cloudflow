#ifndef CF_SOURCE_DNS_CONFIG_H
#define CF_SOURCE_DNS_CONFIG_H

/* WP-DNS07: YAML config loading for the cloudflow-source-dns application, per
 * docs/dns-source.md (DNS-D3/D7/D8) and D6 (docs/architecture.md). Mirrors the
 * DHCP source's config loader (sources/cloudflow-source-dhcp/src/config.{c,h}):
 * a flat libyaml mapping walk (service/capture/queues/redis/dns/stats sections,
 * each a simple key -> scalar or key -> sequence-of-scalars mapping -- no
 * anchors/aliases/multi-doc support needed). Unknown keys (at any level) are
 * logged via cf_log(CF_LOG_WARN, ...) and ignored, not fatal. Missing keys
 * default to the values in configs/examples/dns-source.yaml (the
 * CF_CFG_DEFAULT_* constants in config.c).
 *
 * SECRETS ARE NEVER IN YAML. Redis/Splunk credentials come from the process
 * environment (the systemd unit's EnvironmentFile), not this file; the only
 * environment overrides this loader applies are CF_REDIS_ENDPOINTS /
 * CF_INTERFACE / CF_SOURCE_HOST (non-secret provenance/topology).
 *
 * capture.method accepts only "rxring" -- any other value is a fatal parse
 * error (cf_config_load() logs via cf_log(CF_LOG_ERROR, ...) and returns NULL).
 * capture.filter is informational only (DNS-D1/D7): the builtin VLAN-aware
 * udp/53 + tcp/53 cBPF filter (dns_bpf.c) is always used.
 *
 * redis.expected_stream_dns is used for validation/logging only, not as an
 * output override: the WP-DNS producer (libs/cloudflow-redis) hardcodes stream
 * names via cf_stream_name() and has no per-instance override, so this key is
 * parsed, stored, and compared against cf_stream_name(CF_STREAM_DNS) purely so
 * a mismatch can be logged as a warning. The DNS source always writes exactly
 * one stream, cloudflow:v1:wire:dns.
 */

#include <stddef.h>
#include <stdint.h>

#include "cf_queue_policy.h"

#include "correlation.h" /* CF_DNS_ON_FULL_DROP_NEWEST/_OLDEST */
#include "sampling.h"    /* cf_dns_emit_mode_t */

/* One dns.service_roles entry (WP-DNS11a): a group of server-side DNS service
 * addresses that share an operator-assigned label. Owned by cf_dns_config_t. */
typedef struct {
    char **addresses;      /* heap array of heap IP-literal strings */
    size_t address_count;
    char  *label;          /* operator label, e.g. "recursor" */
} cf_dns_service_role_t;

typedef struct {
    char *service_name;
    char *source_host; /* "" or NULL => main.c falls back to gethostname() */

    char *capture_interface;
    char *capture_method; /* always "rxring" after a successful load */
    uint32_t capture_snaplen;
    char *capture_filter; /* informational only, DNS-D1/D7 */

    uint32_t rx_to_stage_capacity;    /* rx-reader -> event stage queue */
    uint32_t stage_to_redis_capacity; /* event stage -> redis-producer queue */
    cf_queue_full_policy_t queues_on_full;

    char **redis_endpoints; /* heap array of heap "host:port" strings */
    size_t redis_endpoint_count;
    char *redis_expected_stream_dns; /* validation/logging only, see header comment above */
    long long redis_maxlen_approx;
    uint32_t redis_xadd_batch_size;       /* -> cf_redis_producer_config_t.pipeline_max */
    uint32_t redis_xadd_flush_interval_ms;

    /* --- DNS-specific knobs (docs/dns-source.md, DNS-D5/D7/D8) ------------- */

    /* Bounded pending-query correlation table (DNS-D5). */
    uint32_t dns_pending_table_capacity; /* default 262144 */
    uint32_t dns_query_timeout_ms;       /* default 5000 */
    int dns_on_table_full;               /* CF_DNS_ON_FULL_DROP_NEWEST (default) / _OLDEST */

    /* Leg-classifier address sets (DNS-D7). Stored as strings; main.c builds
     * the cf_dns_addr_set_t from them. */
    char **dns_local_service_addresses;
    size_t dns_local_service_address_count;
    char **dns_backend_addresses;
    size_t dns_backend_address_count;

    /* Sampling / emit policy (DNS-D8). */
    cf_dns_emit_mode_t dns_emit_mode; /* CF_DNS_EMIT_ALL (default) / _PREDICATE */
    uint32_t dns_sample_denominator;  /* keep 1 of every N routine txns; 0/1 = keep all */

    /* Service-role map (WP-DNS11a, a DNS-D7 extension): each group maps a set of
     * server-side DNS service IPs to an operator label. Stored as parsed groups;
     * main.c builds the cf_dns_role_map_t. */
    cf_dns_service_role_t *dns_service_roles;
    size_t dns_service_role_count;

    uint32_t stats_interval_s;
    int stats_reset_on_report; /* 0/1 */
} cf_dns_config_t;

/* Loads and validates a cf_dns_config_t from the YAML file at `path`, then
 * applies environment overrides on top (in this order):
 *
 *   CF_REDIS_ENDPOINTS  comma-separated "host:port" list; replaces the entire
 *                       redis.endpoints list.
 *   CF_INTERFACE        replaces capture.interface.
 *   CF_SOURCE_HOST      replaces service.source_host.
 *
 * Returns a heap-allocated, fully-owned config (every pointer field is a
 * private heap allocation -- free with cf_config_free()) on success. Returns
 * NULL on any fatal error (file open/read failure, malformed YAML, root node
 * not a mapping, invalid capture.method), having already logged a clear
 * cf_log(CF_LOG_ERROR, ...) line; the caller (main.c) exits non-zero. */
cf_dns_config_t *cf_config_load(const char *path);

/* Frees a config returned by cf_config_load(). NULL-safe. */
void cf_config_free(cf_dns_config_t *cfg);

#endif
