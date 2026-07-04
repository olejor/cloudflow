/* CUnit tests for the WP-DNS07 DNS source config loader (src/config.c): the
 * libyaml loader cf_config_load() + cf_config_free(), plus its defaults, DNS
 * section, and env overrides. Each case writes a temp YAML file, loads it, and
 * asserts the parsed cf_dns_config_t. Runs clean under ASan (make test-asan):
 * the load/free ownership of every heap string and string list is the key
 * check. Follows the registry/main pattern of the sibling suites. */

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"

/* Writes `body` to a fresh temp file and returns its path in `path` (caller
 * unlinks). Returns 0 on success. */
static int write_tmp(const char *body, char *path, size_t path_len)
{
    int fd;
    FILE *fp;

    snprintf(path, path_len, "/tmp/cf_dns_cfg_test_XXXXXX");
    fd = mkstemp(path);
    if (fd < 0)
        return -1;
    fp = fdopen(fd, "w");
    if (!fp) {
        close(fd);
        return -1;
    }
    fputs(body, fp);
    fclose(fp);
    return 0;
}

/* An empty (but valid) mapping: every field should take its default. */
static void test_defaults_on_empty(void)
{
    char path[64];
    cf_dns_config_t *cfg;

    /* "{}" is a valid YAML mapping root with no sections. */
    CU_ASSERT_EQUAL_FATAL(write_tmp("service: {}\n", path, sizeof(path)), 0);
    cfg = cf_config_load(path);
    unlink(path);

    CU_ASSERT_PTR_NOT_NULL_FATAL(cfg);
    CU_ASSERT_STRING_EQUAL(cfg->service_name, "cloudflow-source-dns");
    CU_ASSERT_STRING_EQUAL(cfg->capture_method, "rxring");
    CU_ASSERT_EQUAL(cfg->rx_to_stage_capacity, 65536u);
    CU_ASSERT_EQUAL(cfg->stage_to_redis_capacity, 65536u);
    CU_ASSERT_EQUAL(cfg->queues_on_full, CF_ONFULL_DROP_NEWEST);
    CU_ASSERT_EQUAL(cfg->redis_endpoint_count, 3u);
    CU_ASSERT_EQUAL(cfg->dns_pending_table_capacity, 262144u);
    CU_ASSERT_EQUAL(cfg->dns_query_timeout_ms, 5000u);
    CU_ASSERT_EQUAL(cfg->dns_on_table_full, CF_DNS_ON_FULL_DROP_NEWEST);
    CU_ASSERT_EQUAL(cfg->dns_emit_mode, CF_DNS_EMIT_ALL);
    CU_ASSERT_EQUAL(cfg->dns_local_service_address_count, 0u);
    CU_ASSERT_EQUAL(cfg->dns_backend_address_count, 0u);
    CU_ASSERT_EQUAL(cfg->stats_interval_s, 10u);
    CU_ASSERT_EQUAL(cfg->stats_reset_on_report, 0);

    cf_config_free(cfg);
}

/* A full config exercises every section, including the DNS knobs and lists. */
static void test_full_config(void)
{
    static const char *body =
        "service:\n"
        "  name: dns-test\n"
        "  source_host: dnsX\n"
        "capture:\n"
        "  interface: eth9\n"
        "  method: rxring\n"
        "  snaplen: 2048\n"
        "queues:\n"
        "  rx_to_stage_capacity: 1024\n"
        "  stage_to_redis_capacity: 2048\n"
        "  on_full: block\n"
        "redis:\n"
        "  endpoints:\n"
        "    - a:1\n"
        "    - b:2\n"
        "  maxlen_approx: 42\n"
        "  xadd_batch_size: 7\n"
        "  xadd_flush_interval_ms: 3\n"
        "dns:\n"
        "  pending_table_capacity: 1000\n"
        "  query_timeout_ms: 250\n"
        "  on_table_full: drop_oldest\n"
        "  local_service_addresses:\n"
        "    - 192.0.2.53\n"
        "    - 2001:db8::53\n"
        "  backend_addresses:\n"
        "    - 198.51.100.10\n"
        "  emit_policy: predicate\n"
        "  sample_denominator: 16\n"
        "stats:\n"
        "  interval_s: 30\n"
        "  reset_on_report: true\n";
    char path[64];
    cf_dns_config_t *cfg;

    CU_ASSERT_EQUAL_FATAL(write_tmp(body, path, sizeof(path)), 0);
    cfg = cf_config_load(path);
    unlink(path);

    CU_ASSERT_PTR_NOT_NULL_FATAL(cfg);
    CU_ASSERT_STRING_EQUAL(cfg->service_name, "dns-test");
    CU_ASSERT_STRING_EQUAL(cfg->source_host, "dnsX");
    CU_ASSERT_STRING_EQUAL(cfg->capture_interface, "eth9");
    CU_ASSERT_EQUAL(cfg->capture_snaplen, 2048u);
    CU_ASSERT_EQUAL(cfg->rx_to_stage_capacity, 1024u);
    CU_ASSERT_EQUAL(cfg->stage_to_redis_capacity, 2048u);
    CU_ASSERT_EQUAL(cfg->queues_on_full, CF_ONFULL_BLOCK);
    CU_ASSERT_EQUAL(cfg->redis_endpoint_count, 2u);
    CU_ASSERT_STRING_EQUAL(cfg->redis_endpoints[0], "a:1");
    CU_ASSERT_STRING_EQUAL(cfg->redis_endpoints[1], "b:2");
    CU_ASSERT_EQUAL(cfg->redis_maxlen_approx, 42);
    CU_ASSERT_EQUAL(cfg->redis_xadd_batch_size, 7u);
    CU_ASSERT_EQUAL(cfg->redis_xadd_flush_interval_ms, 3u);
    CU_ASSERT_EQUAL(cfg->dns_pending_table_capacity, 1000u);
    CU_ASSERT_EQUAL(cfg->dns_query_timeout_ms, 250u);
    CU_ASSERT_EQUAL(cfg->dns_on_table_full, CF_DNS_ON_FULL_DROP_OLDEST);
    CU_ASSERT_EQUAL(cfg->dns_local_service_address_count, 2u);
    CU_ASSERT_STRING_EQUAL(cfg->dns_local_service_addresses[0], "192.0.2.53");
    CU_ASSERT_STRING_EQUAL(cfg->dns_local_service_addresses[1], "2001:db8::53");
    CU_ASSERT_EQUAL(cfg->dns_backend_address_count, 1u);
    CU_ASSERT_STRING_EQUAL(cfg->dns_backend_addresses[0], "198.51.100.10");
    CU_ASSERT_EQUAL(cfg->dns_emit_mode, CF_DNS_EMIT_PREDICATE);
    CU_ASSERT_EQUAL(cfg->dns_sample_denominator, 16u);
    CU_ASSERT_EQUAL(cfg->stats_interval_s, 30u);
    CU_ASSERT_EQUAL(cfg->stats_reset_on_report, 1);

    cf_config_free(cfg);
}

/* dns.service_roles (WP-DNS11a): valid groups are stored; malformed entries (no
 * label, no usable addresses) are logged and skipped, never fatal. */
static void test_service_roles(void)
{
    static const char *body =
        "dns:\n"
        "  service_roles:\n"
        "    - addresses: [192.0.2.53, 192.0.2.54]\n"
        "      label: dnsdist\n"
        "    - addresses: [2001:db8::55]\n"
        "      label: recursor\n"
        "    - addresses: [192.0.2.60]\n"      /* no label -> skipped */
        "    - label: no_addresses\n";         /* no addresses -> skipped */
    char path[64];
    cf_dns_config_t *cfg;

    CU_ASSERT_EQUAL_FATAL(write_tmp(body, path, sizeof(path)), 0);
    cfg = cf_config_load(path);
    unlink(path);

    CU_ASSERT_PTR_NOT_NULL_FATAL(cfg);
    /* Only the two well-formed groups survive. */
    CU_ASSERT_EQUAL_FATAL(cfg->dns_service_role_count, 2u);

    CU_ASSERT_STRING_EQUAL(cfg->dns_service_roles[0].label, "dnsdist");
    CU_ASSERT_EQUAL_FATAL(cfg->dns_service_roles[0].address_count, 2u);
    CU_ASSERT_STRING_EQUAL(cfg->dns_service_roles[0].addresses[0], "192.0.2.53");
    CU_ASSERT_STRING_EQUAL(cfg->dns_service_roles[0].addresses[1], "192.0.2.54");

    CU_ASSERT_STRING_EQUAL(cfg->dns_service_roles[1].label, "recursor");
    CU_ASSERT_EQUAL_FATAL(cfg->dns_service_roles[1].address_count, 1u);
    CU_ASSERT_STRING_EQUAL(cfg->dns_service_roles[1].addresses[0], "2001:db8::55");

    cf_config_free(cfg);
}

/* No dns.service_roles key -> empty map (the default). */
static void test_service_roles_default_empty(void)
{
    char path[64];
    cf_dns_config_t *cfg;

    CU_ASSERT_EQUAL_FATAL(write_tmp("service: {}\n", path, sizeof(path)), 0);
    cfg = cf_config_load(path);
    unlink(path);

    CU_ASSERT_PTR_NOT_NULL_FATAL(cfg);
    CU_ASSERT_EQUAL(cfg->dns_service_role_count, 0u);
    CU_ASSERT_PTR_NULL(cfg->dns_service_roles);

    cf_config_free(cfg);
}

/* An unsupported capture.method is a fatal error (returns NULL). */
static void test_bad_method_is_fatal(void)
{
    char path[64];
    cf_dns_config_t *cfg;

    CU_ASSERT_EQUAL_FATAL(write_tmp("capture:\n  method: pcap\n", path, sizeof(path)), 0);
    cfg = cf_config_load(path);
    unlink(path);

    CU_ASSERT_PTR_NULL(cfg);
    cf_config_free(cfg); /* NULL-safe */
}

/* A missing file is a fatal error (returns NULL, no crash). */
static void test_missing_file_is_fatal(void)
{
    cf_dns_config_t *cfg = cf_config_load("/nonexistent/cf_dns_no_such.yaml");

    CU_ASSERT_PTR_NULL(cfg);
}

/* CF_REDIS_ENDPOINTS replaces the endpoint list wholesale. */
static void test_env_override_endpoints(void)
{
    char path[64];
    cf_dns_config_t *cfg;

    CU_ASSERT_EQUAL_FATAL(write_tmp("service: {}\n", path, sizeof(path)), 0);
    setenv("CF_REDIS_ENDPOINTS", "x:9, y:8", 1);
    cfg = cf_config_load(path);
    unsetenv("CF_REDIS_ENDPOINTS");
    unlink(path);

    CU_ASSERT_PTR_NOT_NULL_FATAL(cfg);
    CU_ASSERT_EQUAL(cfg->redis_endpoint_count, 2u);
    CU_ASSERT_STRING_EQUAL(cfg->redis_endpoints[0], "x:9");
    CU_ASSERT_STRING_EQUAL(cfg->redis_endpoints[1], "y:8");

    cf_config_free(cfg);
}

int main(void)
{
    CU_pSuite suite;
    unsigned int failed;

    if (CU_initialize_registry() != CUE_SUCCESS)
        return (int)CU_get_error();

    suite = CU_add_suite("config", NULL, NULL);
    if (!suite) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    if (!CU_add_test(suite, "defaults on empty config", test_defaults_on_empty) ||
        !CU_add_test(suite, "full config parses every field", test_full_config) ||
        !CU_add_test(suite, "dns.service_roles parses + skips malformed", test_service_roles) ||
        !CU_add_test(suite, "dns.service_roles default empty", test_service_roles_default_empty) ||
        !CU_add_test(suite, "unsupported capture.method is fatal", test_bad_method_is_fatal) ||
        !CU_add_test(suite, "missing file is fatal", test_missing_file_is_fatal) ||
        !CU_add_test(suite, "CF_REDIS_ENDPOINTS override", test_env_override_endpoints)) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();

    failed = CU_get_number_of_tests_failed();
    CU_cleanup_registry();
    return failed > 0 ? 1 : 0;
}
