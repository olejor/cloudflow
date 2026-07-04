#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <yaml.h>

#include "cf_log.h"
#include "cloudflow.h" /* cf_stream_name(), CF_STREAM_DNS */

/* ---------------------------------------------------------------------
 * Defaults, verbatim from configs/examples/dns-source.yaml (D6). Kept as
 * literal constants rather than re-parsing the example file at runtime,
 * matching the DHCP loader's "missing keys get defaults matching the example
 * file's values". stats.interval_s / stats.reset_on_report are not present in
 * that file; their defaults come from the spec (10s, cumulative). */

#define CF_CFG_DEFAULT_SERVICE_NAME "cloudflow-source-dns"
#define CF_CFG_DEFAULT_SOURCE_HOST  "dns01"

#define CF_CFG_DEFAULT_CAPTURE_INTERFACE "eth0"
#define CF_CFG_DEFAULT_CAPTURE_METHOD    "rxring"
#define CF_CFG_DEFAULT_CAPTURE_SNAPLEN   1500u
#define CF_CFG_DEFAULT_CAPTURE_FILTER    "udp port 53 or tcp port 53"

#define CF_CFG_DEFAULT_RX_TO_STAGE_CAP    65536u
#define CF_CFG_DEFAULT_STAGE_TO_REDIS_CAP 65536u

static const char *const CF_CFG_DEFAULT_REDIS_ENDPOINTS[] = {
    "redis01:6379", "redis02:6379", "redis03:6379",
};
#define CF_CFG_DEFAULT_REDIS_ENDPOINT_COUNT 3u

#define CF_CFG_DEFAULT_STREAM_DNS     "cloudflow:v1:wire:dns"
#define CF_CFG_DEFAULT_MAXLEN_APPROX  1000000LL
#define CF_CFG_DEFAULT_XADD_BATCH_SIZE 100u
#define CF_CFG_DEFAULT_XADD_FLUSH_INTERVAL_MS 10u

/* DNS-specific (docs/dns-source.md, DNS-D5/D8). */
#define CF_CFG_DEFAULT_PENDING_TABLE_CAPACITY 262144u
#define CF_CFG_DEFAULT_QUERY_TIMEOUT_MS       5000u
#define CF_CFG_DEFAULT_SAMPLE_DENOMINATOR     0u

#define CF_CFG_DEFAULT_STATS_INTERVAL_S 10u
#define CF_CFG_DEFAULT_STATS_RESET_ON_REPORT 0

/* ---------------------------------------------------------------------
 * Small helpers. */

static char *cfg_strdup(const char *s)
{
    char *out = strdup(s ? s : "");

    if (!out) {
        cf_log(CF_LOG_ERROR, "config: out of memory", NULL);
        exit(1);
    }
    return out;
}

static const char *node_scalar(const yaml_node_t *node)
{
    if (!node || node->type != YAML_SCALAR_NODE)
        return NULL;
    return (const char *)node->data.scalar.value;
}

static void warn_unknown_key(const char *section, const char *key)
{
    cf_log(CF_LOG_WARN, "config: unknown key ignored", "section", section, "key", key ? key : "?",
           NULL);
}

static void warn_bad_value(const char *section, const char *key, const char *value)
{
    cf_log(CF_LOG_WARN, "config: could not parse value, keeping default", "section", section,
           "key", key, "value", value ? value : "?", NULL);
}

/* Parses `s` as an unsigned integer into *out. Returns 0 on success, -1 if
 * `s` is NULL/empty/not a valid non-negative integer (caller keeps the
 * pre-existing default in that case). */
static int parse_u32(const char *s, uint32_t *out)
{
    char *end = NULL;
    unsigned long v;

    if (!s || *s == '\0')
        return -1;

    v = strtoul(s, &end, 10);
    if (end == s || *end != '\0')
        return -1;

    *out = (uint32_t)v;
    return 0;
}

static int parse_i64(const char *s, long long *out)
{
    char *end = NULL;
    long long v;

    if (!s || *s == '\0')
        return -1;

    v = strtoll(s, &end, 10);
    if (end == s || *end != '\0')
        return -1;

    *out = v;
    return 0;
}

static int parse_on_full(const char *s, cf_queue_full_policy_t *out)
{
    if (!s)
        return -1;
    if (strcmp(s, "drop_newest") == 0) {
        *out = CF_ONFULL_DROP_NEWEST;
        return 0;
    }
    if (strcmp(s, "drop_oldest") == 0) {
        *out = CF_ONFULL_DROP_OLDEST;
        return 0;
    }
    if (strcmp(s, "block") == 0) {
        *out = CF_ONFULL_BLOCK;
        return 0;
    }
    return -1;
}

/* Correlation table-full policy (DNS-D5): drop_newest (default) or drop_oldest;
 * "block" has no meaning for the pending table so it is rejected. */
static int parse_on_table_full(const char *s, int *out)
{
    if (!s)
        return -1;
    if (strcmp(s, "drop_newest") == 0) {
        *out = CF_DNS_ON_FULL_DROP_NEWEST;
        return 0;
    }
    if (strcmp(s, "drop_oldest") == 0) {
        *out = CF_DNS_ON_FULL_DROP_OLDEST;
        return 0;
    }
    return -1;
}

static int parse_emit_mode(const char *s, cf_dns_emit_mode_t *out)
{
    if (!s)
        return -1;
    if (strcmp(s, "all") == 0) {
        *out = CF_DNS_EMIT_ALL;
        return 0;
    }
    if (strcmp(s, "predicate") == 0) {
        *out = CF_DNS_EMIT_PREDICATE;
        return 0;
    }
    return -1;
}

static int parse_bool(const char *s, int *out)
{
    if (!s)
        return -1;
    if (strcmp(s, "true") == 0 || strcmp(s, "yes") == 0 || strcmp(s, "1") == 0) {
        *out = 1;
        return 0;
    }
    if (strcmp(s, "false") == 0 || strcmp(s, "no") == 0 || strcmp(s, "0") == 0) {
        *out = 0;
        return 0;
    }
    return -1;
}

/* Frees a heap string list of `count` entries and the array itself. */
static void free_str_list(char **list, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++)
        free(list[i]);
    free(list);
}

/* ---------------------------------------------------------------------
 * Defaults. */

static void set_defaults(cf_dns_config_t *cfg)
{
    size_t i;

    memset(cfg, 0, sizeof(*cfg));

    cfg->service_name = cfg_strdup(CF_CFG_DEFAULT_SERVICE_NAME);
    cfg->source_host = cfg_strdup(CF_CFG_DEFAULT_SOURCE_HOST);

    cfg->capture_interface = cfg_strdup(CF_CFG_DEFAULT_CAPTURE_INTERFACE);
    cfg->capture_method = cfg_strdup(CF_CFG_DEFAULT_CAPTURE_METHOD);
    cfg->capture_snaplen = CF_CFG_DEFAULT_CAPTURE_SNAPLEN;
    cfg->capture_filter = cfg_strdup(CF_CFG_DEFAULT_CAPTURE_FILTER);

    cfg->rx_to_stage_capacity = CF_CFG_DEFAULT_RX_TO_STAGE_CAP;
    cfg->stage_to_redis_capacity = CF_CFG_DEFAULT_STAGE_TO_REDIS_CAP;
    cfg->queues_on_full = CF_ONFULL_DROP_NEWEST;

    cfg->redis_endpoint_count = CF_CFG_DEFAULT_REDIS_ENDPOINT_COUNT;
    cfg->redis_endpoints = calloc(cfg->redis_endpoint_count, sizeof(*cfg->redis_endpoints));
    if (!cfg->redis_endpoints) {
        cf_log(CF_LOG_ERROR, "config: out of memory", NULL);
        exit(1);
    }
    for (i = 0; i < cfg->redis_endpoint_count; i++)
        cfg->redis_endpoints[i] = cfg_strdup(CF_CFG_DEFAULT_REDIS_ENDPOINTS[i]);

    cfg->redis_stream_dns = cfg_strdup(CF_CFG_DEFAULT_STREAM_DNS);
    cfg->redis_maxlen_approx = CF_CFG_DEFAULT_MAXLEN_APPROX;
    cfg->redis_xadd_batch_size = CF_CFG_DEFAULT_XADD_BATCH_SIZE;
    cfg->redis_xadd_flush_interval_ms = CF_CFG_DEFAULT_XADD_FLUSH_INTERVAL_MS;

    cfg->dns_pending_table_capacity = CF_CFG_DEFAULT_PENDING_TABLE_CAPACITY;
    cfg->dns_query_timeout_ms = CF_CFG_DEFAULT_QUERY_TIMEOUT_MS;
    cfg->dns_on_table_full = CF_DNS_ON_FULL_DROP_NEWEST;
    cfg->dns_local_service_addresses = NULL;
    cfg->dns_local_service_address_count = 0;
    cfg->dns_backend_addresses = NULL;
    cfg->dns_backend_address_count = 0;
    cfg->dns_emit_mode = CF_DNS_EMIT_ALL;
    cfg->dns_sample_denominator = CF_CFG_DEFAULT_SAMPLE_DENOMINATOR;
    cfg->dns_service_roles = NULL;
    cfg->dns_service_role_count = 0;

    cfg->stats_interval_s = CF_CFG_DEFAULT_STATS_INTERVAL_S;
    cfg->stats_reset_on_report = CF_CFG_DEFAULT_STATS_RESET_ON_REPORT;
}

/* ---------------------------------------------------------------------
 * Section walkers. */

static void parse_service_section(yaml_document_t *doc, yaml_node_t *node, cf_dns_config_t *cfg)
{
    yaml_node_pair_t *pair;

    if (!node || node->type != YAML_MAPPING_NODE) {
        cf_log(CF_LOG_WARN, "config: 'service' is not a mapping, ignoring", NULL);
        return;
    }

    for (pair = node->data.mapping.pairs.start; pair < node->data.mapping.pairs.top; pair++) {
        yaml_node_t *key = yaml_document_get_node(doc, pair->key);
        yaml_node_t *val = yaml_document_get_node(doc, pair->value);
        const char *k = node_scalar(key);
        const char *v = node_scalar(val);

        if (!k)
            continue;

        if (strcmp(k, "name") == 0) {
            free(cfg->service_name);
            cfg->service_name = cfg_strdup(v);
        } else if (strcmp(k, "source_host") == 0) {
            free(cfg->source_host);
            cfg->source_host = cfg_strdup(v);
        } else {
            warn_unknown_key("service", k);
        }
    }
}

static void parse_capture_section(yaml_document_t *doc, yaml_node_t *node, cf_dns_config_t *cfg)
{
    yaml_node_pair_t *pair;

    if (!node || node->type != YAML_MAPPING_NODE) {
        cf_log(CF_LOG_WARN, "config: 'capture' is not a mapping, ignoring", NULL);
        return;
    }

    for (pair = node->data.mapping.pairs.start; pair < node->data.mapping.pairs.top; pair++) {
        yaml_node_t *key = yaml_document_get_node(doc, pair->key);
        yaml_node_t *val = yaml_document_get_node(doc, pair->value);
        const char *k = node_scalar(key);
        const char *v = node_scalar(val);

        if (!k)
            continue;

        if (strcmp(k, "interface") == 0) {
            free(cfg->capture_interface);
            cfg->capture_interface = cfg_strdup(v);
        } else if (strcmp(k, "method") == 0) {
            free(cfg->capture_method);
            cfg->capture_method = cfg_strdup(v);
        } else if (strcmp(k, "snaplen") == 0) {
            uint32_t parsed;

            if (parse_u32(v, &parsed) == 0)
                cfg->capture_snaplen = parsed;
            else
                warn_bad_value("capture", "snaplen", v);
        } else if (strcmp(k, "filter") == 0) {
            free(cfg->capture_filter);
            cfg->capture_filter = cfg_strdup(v);
        } else {
            warn_unknown_key("capture", k);
        }
    }
}

static void parse_queues_section(yaml_document_t *doc, yaml_node_t *node, cf_dns_config_t *cfg)
{
    yaml_node_pair_t *pair;

    if (!node || node->type != YAML_MAPPING_NODE) {
        cf_log(CF_LOG_WARN, "config: 'queues' is not a mapping, ignoring", NULL);
        return;
    }

    for (pair = node->data.mapping.pairs.start; pair < node->data.mapping.pairs.top; pair++) {
        yaml_node_t *key = yaml_document_get_node(doc, pair->key);
        yaml_node_t *val = yaml_document_get_node(doc, pair->value);
        const char *k = node_scalar(key);
        const char *v = node_scalar(val);

        if (!k)
            continue;

        if (strcmp(k, "rx_to_stage_capacity") == 0) {
            uint32_t parsed;

            if (parse_u32(v, &parsed) == 0)
                cfg->rx_to_stage_capacity = parsed;
            else
                warn_bad_value("queues", "rx_to_stage_capacity", v);
        } else if (strcmp(k, "stage_to_redis_capacity") == 0) {
            uint32_t parsed;

            if (parse_u32(v, &parsed) == 0)
                cfg->stage_to_redis_capacity = parsed;
            else
                warn_bad_value("queues", "stage_to_redis_capacity", v);
        } else if (strcmp(k, "on_full") == 0) {
            cf_queue_full_policy_t parsed;

            if (parse_on_full(v, &parsed) == 0)
                cfg->queues_on_full = parsed;
            else
                warn_bad_value("queues", "on_full", v);
        } else {
            warn_unknown_key("queues", k);
        }
    }
}

/* Parses a YAML sequence-of-scalars into a fresh heap string list, replacing
 * (*list_out, *count_out). On a non-sequence / empty / all-non-scalar node the
 * existing list is kept and a warning logged. `label` names the key for logs. */
static void parse_str_list(yaml_document_t *doc, yaml_node_t *node, const char *label,
                           char ***list_out, size_t *count_out)
{
    yaml_node_item_t *item;
    size_t count;
    size_t i;
    char **list;

    if (!node || node->type != YAML_SEQUENCE_NODE) {
        cf_log(CF_LOG_WARN, "config: value is not a list, keeping default", "key", label, NULL);
        return;
    }

    count = (size_t)(node->data.sequence.items.top - node->data.sequence.items.start);
    if (count == 0) {
        /* An explicit empty list is meaningful for the DNS address sets ("no
         * configured addresses"); accept it and clear the default. */
        free_str_list(*list_out, *count_out);
        *list_out = NULL;
        *count_out = 0;
        return;
    }

    list = calloc(count, sizeof(*list));
    if (!list) {
        cf_log(CF_LOG_ERROR, "config: out of memory", NULL);
        exit(1);
    }

    i = 0;
    for (item = node->data.sequence.items.start; item < node->data.sequence.items.top; item++) {
        yaml_node_t *elem = yaml_document_get_node(doc, *item);
        const char *v = node_scalar(elem);

        if (!v) {
            cf_log(CF_LOG_WARN, "config: list entry is not a scalar, skipping", "key", label, NULL);
            continue;
        }
        list[i++] = cfg_strdup(v);
    }

    if (i == 0) {
        free_str_list(list, count);
        cf_log(CF_LOG_WARN, "config: list had no usable entries, keeping default", "key", label,
               NULL);
        return;
    }

    free_str_list(*list_out, *count_out);
    *list_out = list;
    *count_out = i;
}

/* Frees a service-role group array and everything it owns. */
static void free_service_roles(cf_dns_service_role_t *roles, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++) {
        free_str_list(roles[i].addresses, roles[i].address_count);
        free(roles[i].label);
    }
    free(roles);
}

/* Parses a `dns.service_roles` YAML sequence (WP-DNS11a): a list of mappings,
 * each with `addresses: [ip, ...]` and `label: <string>`. Malformed entries (a
 * non-mapping, a missing/empty label, or no usable addresses) are logged and
 * skipped -- never fatal. Replaces (*roles_out, *count_out). */
static void parse_service_roles(yaml_document_t *doc, yaml_node_t *node,
                                cf_dns_service_role_t **roles_out, size_t *count_out)
{
    yaml_node_item_t *item;
    size_t cap;
    cf_dns_service_role_t *roles;
    size_t count = 0;

    if (!node || node->type != YAML_SEQUENCE_NODE) {
        cf_log(CF_LOG_WARN, "config: dns.service_roles is not a list, keeping default", NULL);
        return;
    }

    cap = (size_t)(node->data.sequence.items.top - node->data.sequence.items.start);
    if (cap == 0) {
        /* An explicit empty list clears the map (no service roles). */
        free_service_roles(*roles_out, *count_out);
        *roles_out = NULL;
        *count_out = 0;
        return;
    }

    roles = calloc(cap, sizeof(*roles));
    if (!roles) {
        cf_log(CF_LOG_ERROR, "config: out of memory", NULL);
        exit(1);
    }

    for (item = node->data.sequence.items.start; item < node->data.sequence.items.top; item++) {
        yaml_node_t *entry = yaml_document_get_node(doc, *item);
        yaml_node_pair_t *pair;
        yaml_node_t *addrs_node = NULL;
        const char *label = NULL;
        char **addresses = NULL;
        size_t address_count = 0;

        if (!entry || entry->type != YAML_MAPPING_NODE) {
            cf_log(CF_LOG_WARN,
                   "config: dns.service_roles entry is not a mapping, skipping", NULL);
            continue;
        }

        for (pair = entry->data.mapping.pairs.start; pair < entry->data.mapping.pairs.top;
             pair++) {
            yaml_node_t *key = yaml_document_get_node(doc, pair->key);
            yaml_node_t *val = yaml_document_get_node(doc, pair->value);
            const char *k = node_scalar(key);

            if (!k)
                continue;
            if (strcmp(k, "addresses") == 0)
                addrs_node = val;
            else if (strcmp(k, "label") == 0)
                label = node_scalar(val);
            else
                warn_unknown_key("dns.service_roles", k);
        }

        if (!label || label[0] == '\0') {
            cf_log(CF_LOG_WARN,
                   "config: dns.service_roles entry has no 'label', skipping", NULL);
            continue;
        }

        /* parse_str_list clears+replaces the (NULL, 0) target with the parsed
         * scalar list, or keeps it (NULL) on a non-sequence node. */
        parse_str_list(doc, addrs_node, "dns.service_roles.addresses", &addresses,
                       &address_count);
        if (address_count == 0) {
            cf_log(CF_LOG_WARN,
                   "config: dns.service_roles entry has no usable 'addresses', skipping",
                   "label", label, NULL);
            free_str_list(addresses, address_count);
            continue;
        }

        roles[count].addresses = addresses;
        roles[count].address_count = address_count;
        roles[count].label = cfg_strdup(label);
        count++;
    }

    if (count == 0) {
        free_service_roles(roles, 0);
        cf_log(CF_LOG_WARN,
               "config: dns.service_roles had no usable entries, keeping default", NULL);
        return;
    }

    free_service_roles(*roles_out, *count_out);
    *roles_out = roles;
    *count_out = count;
}

static void parse_redis_section(yaml_document_t *doc, yaml_node_t *node, cf_dns_config_t *cfg)
{
    yaml_node_pair_t *pair;

    if (!node || node->type != YAML_MAPPING_NODE) {
        cf_log(CF_LOG_WARN, "config: 'redis' is not a mapping, ignoring", NULL);
        return;
    }

    for (pair = node->data.mapping.pairs.start; pair < node->data.mapping.pairs.top; pair++) {
        yaml_node_t *key = yaml_document_get_node(doc, pair->key);
        yaml_node_t *val = yaml_document_get_node(doc, pair->value);
        const char *k = node_scalar(key);
        const char *v = node_scalar(val);

        if (!k)
            continue;

        if (strcmp(k, "endpoints") == 0) {
            parse_str_list(doc, val, "redis.endpoints", &cfg->redis_endpoints,
                           &cfg->redis_endpoint_count);
        } else if (strcmp(k, "stream_dns") == 0) {
            free(cfg->redis_stream_dns);
            cfg->redis_stream_dns = cfg_strdup(v);
        } else if (strcmp(k, "maxlen_approx") == 0) {
            long long parsed;

            if (parse_i64(v, &parsed) == 0)
                cfg->redis_maxlen_approx = parsed;
            else
                warn_bad_value("redis", "maxlen_approx", v);
        } else if (strcmp(k, "xadd_batch_size") == 0) {
            uint32_t parsed;

            if (parse_u32(v, &parsed) == 0)
                cfg->redis_xadd_batch_size = parsed;
            else
                warn_bad_value("redis", "xadd_batch_size", v);
        } else if (strcmp(k, "xadd_flush_interval_ms") == 0) {
            uint32_t parsed;

            if (parse_u32(v, &parsed) == 0)
                cfg->redis_xadd_flush_interval_ms = parsed;
            else
                warn_bad_value("redis", "xadd_flush_interval_ms", v);
        } else {
            warn_unknown_key("redis", k);
        }
    }
}

static void parse_dns_section(yaml_document_t *doc, yaml_node_t *node, cf_dns_config_t *cfg)
{
    yaml_node_pair_t *pair;

    if (!node || node->type != YAML_MAPPING_NODE) {
        cf_log(CF_LOG_WARN, "config: 'dns' is not a mapping, ignoring", NULL);
        return;
    }

    for (pair = node->data.mapping.pairs.start; pair < node->data.mapping.pairs.top; pair++) {
        yaml_node_t *key = yaml_document_get_node(doc, pair->key);
        yaml_node_t *val = yaml_document_get_node(doc, pair->value);
        const char *k = node_scalar(key);
        const char *v = node_scalar(val);

        if (!k)
            continue;

        if (strcmp(k, "pending_table_capacity") == 0) {
            uint32_t parsed;

            if (parse_u32(v, &parsed) == 0 && parsed > 0)
                cfg->dns_pending_table_capacity = parsed;
            else
                warn_bad_value("dns", "pending_table_capacity", v);
        } else if (strcmp(k, "query_timeout_ms") == 0) {
            uint32_t parsed;

            if (parse_u32(v, &parsed) == 0 && parsed > 0)
                cfg->dns_query_timeout_ms = parsed;
            else
                warn_bad_value("dns", "query_timeout_ms", v);
        } else if (strcmp(k, "on_table_full") == 0) {
            int parsed;

            if (parse_on_table_full(v, &parsed) == 0)
                cfg->dns_on_table_full = parsed;
            else
                warn_bad_value("dns", "on_table_full", v);
        } else if (strcmp(k, "local_service_addresses") == 0) {
            parse_str_list(doc, val, "dns.local_service_addresses",
                           &cfg->dns_local_service_addresses,
                           &cfg->dns_local_service_address_count);
        } else if (strcmp(k, "backend_addresses") == 0) {
            parse_str_list(doc, val, "dns.backend_addresses", &cfg->dns_backend_addresses,
                           &cfg->dns_backend_address_count);
        } else if (strcmp(k, "emit_policy") == 0) {
            cf_dns_emit_mode_t parsed;

            if (parse_emit_mode(v, &parsed) == 0)
                cfg->dns_emit_mode = parsed;
            else
                warn_bad_value("dns", "emit_policy", v);
        } else if (strcmp(k, "sample_denominator") == 0) {
            uint32_t parsed;

            if (parse_u32(v, &parsed) == 0)
                cfg->dns_sample_denominator = parsed;
            else
                warn_bad_value("dns", "sample_denominator", v);
        } else if (strcmp(k, "service_roles") == 0) {
            parse_service_roles(doc, val, &cfg->dns_service_roles,
                                &cfg->dns_service_role_count);
        } else {
            warn_unknown_key("dns", k);
        }
    }
}

static void parse_stats_section(yaml_document_t *doc, yaml_node_t *node, cf_dns_config_t *cfg)
{
    yaml_node_pair_t *pair;

    if (!node || node->type != YAML_MAPPING_NODE) {
        cf_log(CF_LOG_WARN, "config: 'stats' is not a mapping, ignoring", NULL);
        return;
    }

    for (pair = node->data.mapping.pairs.start; pair < node->data.mapping.pairs.top; pair++) {
        yaml_node_t *key = yaml_document_get_node(doc, pair->key);
        yaml_node_t *val = yaml_document_get_node(doc, pair->value);
        const char *k = node_scalar(key);
        const char *v = node_scalar(val);

        if (!k)
            continue;

        if (strcmp(k, "interval_s") == 0) {
            uint32_t parsed;

            if (parse_u32(v, &parsed) == 0 && parsed > 0)
                cfg->stats_interval_s = parsed;
            else
                warn_bad_value("stats", "interval_s", v);
        } else if (strcmp(k, "reset_on_report") == 0) {
            int parsed;

            if (parse_bool(v, &parsed) == 0)
                cfg->stats_reset_on_report = parsed;
            else
                warn_bad_value("stats", "reset_on_report", v);
        } else {
            warn_unknown_key("stats", k);
        }
    }
}

/* ---------------------------------------------------------------------
 * Env overrides, applied after the YAML file is fully parsed. Secrets are
 * never accepted here -- only non-secret endpoints/interface/host. */

static void apply_env_overrides(cf_dns_config_t *cfg)
{
    const char *env;

    env = getenv("CF_REDIS_ENDPOINTS");
    if (env && *env) {
        char *copy = cfg_strdup(env);
        char *saveptr = NULL;
        char *tok;
        char **list = NULL;
        size_t count = 0;
        size_t cap = 0;

        for (tok = strtok_r(copy, ",", &saveptr); tok; tok = strtok_r(NULL, ",", &saveptr)) {
            while (*tok == ' ' || *tok == '\t')
                tok++;
            if (*tok == '\0')
                continue;

            if (count == cap) {
                size_t new_cap = cap == 0 ? 4 : cap * 2;
                char **grown = realloc(list, new_cap * sizeof(*list));

                if (!grown) {
                    cf_log(CF_LOG_ERROR, "config: out of memory", NULL);
                    exit(1);
                }
                list = grown;
                cap = new_cap;
            }
            list[count++] = cfg_strdup(tok);
        }
        free(copy);

        if (count > 0) {
            free_str_list(cfg->redis_endpoints, cfg->redis_endpoint_count);
            cfg->redis_endpoints = list;
            cfg->redis_endpoint_count = count;
            cf_log(CF_LOG_INFO, "config: CF_REDIS_ENDPOINTS override applied", "endpoints", env,
                   NULL);
        } else {
            free(list);
            cf_log(CF_LOG_WARN, "config: CF_REDIS_ENDPOINTS set but had no usable entries, ignoring",
                   NULL);
        }
    }

    env = getenv("CF_INTERFACE");
    if (env && *env) {
        free(cfg->capture_interface);
        cfg->capture_interface = cfg_strdup(env);
        cf_log(CF_LOG_INFO, "config: CF_INTERFACE override applied", "interface", env, NULL);
    }

    env = getenv("CF_SOURCE_HOST");
    if (env && *env) {
        free(cfg->source_host);
        cfg->source_host = cfg_strdup(env);
        cf_log(CF_LOG_INFO, "config: CF_SOURCE_HOST override applied", "source_host", env, NULL);
    }
}

/* ---------------------------------------------------------------------
 * Public API. */

void cf_config_free(cf_dns_config_t *cfg)
{
    if (!cfg)
        return;

    free(cfg->service_name);
    free(cfg->source_host);
    free(cfg->capture_interface);
    free(cfg->capture_method);
    free(cfg->capture_filter);

    free_str_list(cfg->redis_endpoints, cfg->redis_endpoint_count);
    free(cfg->redis_stream_dns);

    free_str_list(cfg->dns_local_service_addresses, cfg->dns_local_service_address_count);
    free_str_list(cfg->dns_backend_addresses, cfg->dns_backend_address_count);
    free_service_roles(cfg->dns_service_roles, cfg->dns_service_role_count);

    free(cfg);
}

cf_dns_config_t *cf_config_load(const char *path)
{
    FILE *fp;
    yaml_parser_t parser;
    yaml_document_t doc;
    yaml_node_t *root;
    cf_dns_config_t *cfg;
    int have_doc = 0;

    if (!path) {
        cf_log(CF_LOG_ERROR, "config: no path given", NULL);
        return NULL;
    }

    fp = fopen(path, "rb");
    if (!fp) {
        cf_log(CF_LOG_ERROR, "config: failed to open file", "path", path, "error", strerror(errno),
               NULL);
        return NULL;
    }

    if (!yaml_parser_initialize(&parser)) {
        cf_log(CF_LOG_ERROR, "config: yaml_parser_initialize failed", "path", path, NULL);
        fclose(fp);
        return NULL;
    }

    yaml_parser_set_input_file(&parser, fp);

    if (!yaml_parser_load(&parser, &doc)) {
        cf_log(CF_LOG_ERROR, "config: YAML parse error", "path", path, "problem",
               parser.problem ? parser.problem : "unknown", NULL);
        yaml_parser_delete(&parser);
        fclose(fp);
        return NULL;
    }
    have_doc = 1;

    yaml_parser_delete(&parser);
    fclose(fp);

    cfg = calloc(1, sizeof(*cfg));
    if (!cfg) {
        cf_log(CF_LOG_ERROR, "config: out of memory", NULL);
        yaml_document_delete(&doc);
        return NULL;
    }
    set_defaults(cfg);

    root = yaml_document_get_root_node(&doc);
    if (!root) {
        cf_log(CF_LOG_ERROR, "config: empty YAML document", "path", path, NULL);
        yaml_document_delete(&doc);
        cf_config_free(cfg);
        return NULL;
    }

    if (root->type != YAML_MAPPING_NODE) {
        cf_log(CF_LOG_ERROR, "config: root node is not a mapping", "path", path, NULL);
        yaml_document_delete(&doc);
        cf_config_free(cfg);
        return NULL;
    }

    {
        yaml_node_pair_t *pair;

        for (pair = root->data.mapping.pairs.start; pair < root->data.mapping.pairs.top; pair++) {
            yaml_node_t *key = yaml_document_get_node(&doc, pair->key);
            yaml_node_t *val = yaml_document_get_node(&doc, pair->value);
            const char *k = node_scalar(key);

            if (!k)
                continue;

            if (strcmp(k, "service") == 0)
                parse_service_section(&doc, val, cfg);
            else if (strcmp(k, "capture") == 0)
                parse_capture_section(&doc, val, cfg);
            else if (strcmp(k, "queues") == 0)
                parse_queues_section(&doc, val, cfg);
            else if (strcmp(k, "redis") == 0)
                parse_redis_section(&doc, val, cfg);
            else if (strcmp(k, "dns") == 0)
                parse_dns_section(&doc, val, cfg);
            else if (strcmp(k, "stats") == 0)
                parse_stats_section(&doc, val, cfg);
            else
                warn_unknown_key("top-level", k);
        }
    }

    if (have_doc)
        yaml_document_delete(&doc);

    /* capture.method: only "rxring" is supported (DNS-D7). */
    if (strcmp(cfg->capture_method, "rxring") != 0) {
        cf_log(CF_LOG_ERROR, "config: capture.method must be 'rxring'", "path", path, "value",
               cfg->capture_method, NULL);
        cf_config_free(cfg);
        return NULL;
    }

    /* DNS-D1/D7: capture.filter is informational only -- the builtin VLAN-aware
     * cBPF filter (dns_bpf.c) is always used regardless of this string. */
    if (cfg->capture_filter && cfg->capture_filter[0] != '\0') {
        cf_log(CF_LOG_WARN,
               "config: capture.filter is informational in v0.2 (DNS-D1); the builtin DNS BPF "
               "filter (udp/53 + tcp/53) is always used",
               "configured_filter", cfg->capture_filter, NULL);
    }

    /* redis.stream_dns is likewise informational -- warn if it does not match
     * what the producer library actually uses (DNS-D3). */
    if (strcmp(cfg->redis_stream_dns, cf_stream_name(CF_STREAM_DNS)) != 0) {
        cf_log(CF_LOG_WARN,
               "config: redis.stream_dns does not match the built-in stream name and is "
               "informational only",
               "configured", cfg->redis_stream_dns, "actual", cf_stream_name(CF_STREAM_DNS), NULL);
    }

    /* PREDICATE emit policy with no denominator degrades to "keep all routine
     * txns" -- harmless but worth surfacing. */
    if (cfg->dns_emit_mode == CF_DNS_EMIT_PREDICATE && cfg->dns_sample_denominator <= 1) {
        cf_log(CF_LOG_WARN,
               "config: dns.emit_policy is 'predicate' but dns.sample_denominator <= 1, so routine "
               "A/AAAA NOERROR transactions are all emitted (no sampling)",
               NULL);
    }

    apply_env_overrides(cfg);

    return cfg;
}
