/* CUnit tests for the WP-11 DHCP source config loader (src/config.c): the
 * libyaml loader cf_config_load() + cf_config_free(), its defaults, and the L2
 * parse_u32 range validation. Each case writes a temp YAML file, loads it, and
 * asserts the parsed cf_source_config_t. Runs clean under ASan (make test-asan):
 * the load/free ownership of every heap string and string list is a key check.
 * Mirrors the DNS source's tests/config_test.c. */

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

    snprintf(path, path_len, "/tmp/cf_dhcp_cfg_test_XXXXXX");
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
    cf_source_config_t *cfg;

    CU_ASSERT_EQUAL_FATAL(write_tmp("service: {}\n", path, sizeof(path)), 0);
    cfg = cf_config_load(path);
    unlink(path);

    CU_ASSERT_PTR_NOT_NULL_FATAL(cfg);
    CU_ASSERT_STRING_EQUAL(cfg->service_name, "cloudflow-source-dhcp");
    CU_ASSERT_STRING_EQUAL(cfg->capture_method, "rxring");
    CU_ASSERT_EQUAL(cfg->capture_snaplen, 1500u);
    CU_ASSERT_EQUAL(cfg->rx_to_formatter_capacity, 65536u);
    CU_ASSERT_EQUAL(cfg->formatter_to_redis_capacity, 65536u);
    CU_ASSERT_EQUAL(cfg->stats_interval_s, 10u);
    CU_ASSERT_EQUAL(cfg->stats_reset_on_report, 0);

    cf_config_free(cfg);
}

/* A well-formed u32 field is parsed verbatim. */
static void test_valid_u32_parsed(void)
{
    static const char *body =
        "capture:\n"
        "  snaplen: 2048\n"
        "queues:\n"
        "  rx_to_formatter_capacity: 1024\n"
        "  formatter_to_redis_capacity: 2048\n";
    char path[64];
    cf_source_config_t *cfg;

    CU_ASSERT_EQUAL_FATAL(write_tmp(body, path, sizeof(path)), 0);
    cfg = cf_config_load(path);
    unlink(path);

    CU_ASSERT_PTR_NOT_NULL_FATAL(cfg);
    CU_ASSERT_EQUAL(cfg->capture_snaplen, 2048u);
    CU_ASSERT_EQUAL(cfg->rx_to_formatter_capacity, 1024u);
    CU_ASSERT_EQUAL(cfg->formatter_to_redis_capacity, 2048u);

    cf_config_free(cfg);
}

/* parse_u32 range validation (L2): a u32 field whose value overflows uint32_t,
 * is negative, or carries trailing junk is rejected (warn_bad_value path) and
 * keeps its default -- it must NOT silently truncate or wrap. snaplen defaults
 * to 1500; the two queue capacities to 65536. */
static void test_u32_out_of_range_keeps_default(void)
{
    static const char *body =
        "capture:\n"
        "  snaplen: 5000000000\n"               /* > UINT32_MAX -> reject */
        "queues:\n"
        "  rx_to_formatter_capacity: -1\n"       /* negative -> reject (would wrap) */
        "  formatter_to_redis_capacity: 12x\n";  /* trailing junk -> reject */
    char path[64];
    cf_source_config_t *cfg;

    CU_ASSERT_EQUAL_FATAL(write_tmp(body, path, sizeof(path)), 0);
    cfg = cf_config_load(path);
    unlink(path);

    CU_ASSERT_PTR_NOT_NULL_FATAL(cfg);
    CU_ASSERT_EQUAL(cfg->capture_snaplen, 1500u);
    CU_ASSERT_EQUAL(cfg->rx_to_formatter_capacity, 65536u);
    CU_ASSERT_EQUAL(cfg->formatter_to_redis_capacity, 65536u);

    cf_config_free(cfg);
}

/* An in-range u32 at the uint32_t boundary is accepted verbatim. */
static void test_u32_max_boundary_accepted(void)
{
    static const char *body =
        "queues:\n"
        "  rx_to_formatter_capacity: 4294967295\n"; /* UINT32_MAX -> accept */
    char path[64];
    cf_source_config_t *cfg;

    CU_ASSERT_EQUAL_FATAL(write_tmp(body, path, sizeof(path)), 0);
    cfg = cf_config_load(path);
    unlink(path);

    CU_ASSERT_PTR_NOT_NULL_FATAL(cfg);
    CU_ASSERT_EQUAL(cfg->rx_to_formatter_capacity, 4294967295u);

    cf_config_free(cfg);
}

/* An unsupported capture.method is a fatal error (returns NULL). */
static void test_bad_method_is_fatal(void)
{
    char path[64];
    cf_source_config_t *cfg;

    CU_ASSERT_EQUAL_FATAL(write_tmp("capture:\n  method: pcap\n", path, sizeof(path)), 0);
    cfg = cf_config_load(path);
    unlink(path);

    CU_ASSERT_PTR_NULL(cfg);
    cf_config_free(cfg); /* NULL-safe */
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
        !CU_add_test(suite, "valid u32 fields parse", test_valid_u32_parsed) ||
        !CU_add_test(suite, "parse_u32 out-of-range/negative keeps default",
                     test_u32_out_of_range_keeps_default) ||
        !CU_add_test(suite, "parse_u32 UINT32_MAX boundary accepted",
                     test_u32_max_boundary_accepted) ||
        !CU_add_test(suite, "unsupported capture.method is fatal", test_bad_method_is_fatal)) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();

    failed = CU_get_number_of_tests_failed();
    CU_cleanup_registry();
    return failed > 0 ? 1 : 0;
}
