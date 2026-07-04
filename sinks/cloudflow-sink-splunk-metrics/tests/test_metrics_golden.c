/* WP-M02 metrics golden suite.
 *
 * For each committed golden (tests/golden/<name>.jsonl), read the packed
 * CloudFlowEvent produced by the Python golden generator
 * (tests/fixtures/<name>.pb -- rebuilt by `make fixtures` /
 * generate_fixtures.py), run the C metrics transform, and compare the emitted
 * newline-delimited Splunk metric points against the golden with a STRUCTURAL,
 * order-independent compare (python3: parse each line to an object, compare the
 * sorted set of objects). Proves the metric mapping (docs/splunk-metrics.md).
 */

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "metrics_transform.h"

#include "cloudflow/v1/envelope.pb-c.h"

/* Build a config with all metrics enabled and the default dimension controls
 * (server_ip on, qtype on, client_key off). Uses string literals and is never
 * freed, mirroring the event sink's golden test's stack config. */
static void make_config(cf_config_t *c)
{
    memset(c, 0, sizeof(*c));
    c->metrics_index = (char *)"cloudflow_metrics";
    c->enabled_metrics = NULL;
    c->enabled_count = 0;
    c->dim_dns_server_ip = 1;
    c->dim_dns_qtype = 1;
    c->dim_dhcp_client_key = 0;
}

static uint8_t *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    long n;
    uint8_t *buf;

    if (!f)
        return NULL;
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = malloc((size_t)n ? (size_t)n : 1);
    if (buf && n > 0 && fread(buf, 1, (size_t)n, f) != (size_t)n) {
        free(buf);
        buf = NULL;
    }
    fclose(f);
    *len = (size_t)n;
    return buf;
}

/* Structural, order-independent equality of two newline-delimited JSON files:
 * parse each non-empty line as an object, compare the multisets. Returns 1 if
 * equal. */
static int metric_sets_equal(const char *path_a, const char *path_b)
{
    char cmd[2048];
    int rc;

    snprintf(cmd, sizeof(cmd),
             "python3 -c 'import json,sys\n"
             "def load(p):\n"
             "    with open(p) as f:\n"
             "        objs=[json.loads(l) for l in f if l.strip()]\n"
             "    return sorted(json.dumps(o,sort_keys=True) for o in objs)\n"
             "sys.exit(0 if load(sys.argv[1])==load(sys.argv[2]) else 1)' '%s' '%s'",
             path_a, path_b);
    rc = system(cmd);
    return rc == 0;
}

static char *run_transform(const char *pb_name, cf_config_t *cfg, size_t *nlines)
{
    char pb_path[256];
    uint8_t *buf;
    size_t len = 0;
    Cloudflow__V1__CloudFlowEvent *ev;
    cf_sink_buf_t out;
    char *result = NULL;
    int rc;

    snprintf(pb_path, sizeof(pb_path), "tests/fixtures/%s.pb", pb_name);
    buf = read_file(pb_path, &len);
    CU_ASSERT_PTR_NOT_NULL_FATAL(buf);

    ev = cloudflow__v1__cloud_flow_event__unpack(NULL, len, buf);
    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);

    memset(&out, 0, sizeof(out));
    rc = cf_metrics_transform(cfg, ev, "cloudflow:v1:wire:test", &out);
    CU_ASSERT_EQUAL(rc, 0);

    if (nlines) {
        size_t n = 0;
        if (out.data && out.len > 0) {
            n = 1;
            for (size_t i = 0; i < out.len; i++)
                if (out.data[i] == '\n')
                    n++;
        }
        *nlines = n;
    }

    if (out.data)
        result = strdup(out.data);

    cf_sink_buf_free(&out);
    cloudflow__v1__cloud_flow_event__free_unpacked(ev, NULL);
    free(buf);
    return result;
}

static void run_golden_case(const char *pb_name, const char *golden_name)
{
    char golden_path[256], out_path[256];
    cf_config_t cfg;
    char *lines;
    FILE *out;

    snprintf(golden_path, sizeof(golden_path), "tests/golden/%s.jsonl", golden_name);
    snprintf(out_path, sizeof(out_path), "build/golden_out_%s.jsonl", golden_name);

    make_config(&cfg);
    lines = run_transform(pb_name, &cfg, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(lines);

    out = fopen(out_path, "wb");
    CU_ASSERT_PTR_NOT_NULL_FATAL(out);
    fprintf(out, "%s\n", lines);
    fclose(out);

    CU_ASSERT_TRUE(metric_sets_equal(out_path, golden_path));
    free(lines);
}

static void test_dns_transaction_service_role(void)
{
    /* DNS observed with service_role: two points (transactions_total + rtt). */
    run_golden_case("dns_transaction_service_role", "dns_transaction_service_role");
}

static void test_dhcpv4_discover(void)
{
    /* DHCPv4 DISCOVER: one dhcp.events_total point (client key opt-out). */
    run_golden_case("dhcpv4_discover", "dhcpv4_discover");
}

static void test_enabled_metrics_allowlist(void)
{
    /* Allowlisting only dns.transactions_total drops the rtt point. */
    cf_config_t cfg;
    char *only[] = {(char *)CF_METRIC_DNS_TRANSACTIONS_TOTAL};
    size_t nlines = 0;
    char *lines;

    make_config(&cfg);
    cfg.enabled_metrics = only;
    cfg.enabled_count = 1;

    lines = run_transform("dns_transaction_service_role", &cfg, &nlines);
    CU_ASSERT_PTR_NOT_NULL_FATAL(lines);
    CU_ASSERT_EQUAL(nlines, 1);
    CU_ASSERT_PTR_NOT_NULL(strstr(lines, "metric_name:dns.transactions_total"));
    CU_ASSERT_PTR_NULL(strstr(lines, "metric_name:dns.rtt_seconds"));
    free(lines);
}

static void test_dhcp_client_key_opt_in(void)
{
    /* The high-cardinality cf_client_key dimension appears only when enabled. */
    cf_config_t cfg;
    char *lines;

    make_config(&cfg);
    lines = run_transform("dhcpv4_discover", &cfg, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(lines);
    CU_ASSERT_PTR_NULL(strstr(lines, "cf_client_key"));
    free(lines);

    make_config(&cfg);
    cfg.dim_dhcp_client_key = 1;
    lines = run_transform("dhcpv4_discover", &cfg, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(lines);
    CU_ASSERT_PTR_NOT_NULL(strstr(lines, "cf_client_key"));
    free(lines);
}

int main(void)
{
    CU_pSuite suite;
    unsigned int failed;

    if (CU_initialize_registry() != CUE_SUCCESS)
        return (int)CU_get_error();

    suite = CU_add_suite("metrics_golden", NULL, NULL);
    if (!suite ||
        !CU_add_test(suite, "dns transaction service_role golden",
                     test_dns_transaction_service_role) ||
        !CU_add_test(suite, "dhcpv4 discover golden", test_dhcpv4_discover) ||
        !CU_add_test(suite, "enabled_metrics allowlist", test_enabled_metrics_allowlist) ||
        !CU_add_test(suite, "dhcp client key opt-in", test_dhcp_client_key_opt_in)) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    failed = CU_get_number_of_tests_failed();
    CU_cleanup_registry();
    return failed > 0 ? 1 : 0;
}
