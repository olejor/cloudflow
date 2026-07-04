/* WP-17 golden compatibility suite.
 *
 * For each committed golden (tests/golden/<name>.json), read the packed
 * CloudFlowEvent produced by the Python golden generator
 * (tests/fixtures/<name>.pb -- rebuilt by `make fixtures` /
 * generate_fixtures.py), run the C transform, and compare the emitted HEC
 * JSON against the golden with a STRUCTURAL compare (python3 json equality,
 * not byte order). Proves the C transform is compatible with the WP-12
 * Python mapping (docs/splunk-output.md, "Mapping compatibility").
 */

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "transform.h"

#include "cloudflow/v1/envelope.pb-c.h"

static const char *ST_KEYS[] = {"dhcpv4", "dhcpv6", "dns"};
static const char *ST_VALS[] = {"cloudflow:dhcpv4", "cloudflow:dhcpv6", "cloudflow:dns"};

static void make_config(cf_splunk_config_t *s, int include_raw)
{
    memset(s, 0, sizeof(*s));
    s->index = (char *)"network";
    s->st_keys = (char **)ST_KEYS;
    s->st_vals = (char **)ST_VALS;
    s->st_count = 3;
    s->include_raw_payload = include_raw;
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

/* Structural JSON equality via python3. Returns 1 if equal. */
static int json_equal(const char *path_a, const char *path_b)
{
    char cmd[2048];
    int rc;

    snprintf(cmd, sizeof(cmd),
             "python3 -c 'import json,sys; "
             "a=json.load(open(sys.argv[1])); b=json.load(open(sys.argv[2])); "
             "sys.exit(0 if a==b else 1)' '%s' '%s'",
             path_a, path_b);
    rc = system(cmd);
    return rc == 0;
}

static void run_case(const char *pb_name, const char *golden_name, const char *stream,
                     int include_raw)
{
    char pb_path[256], golden_path[256], out_path[256];
    uint8_t *buf;
    size_t len = 0;
    Cloudflow__V1__CloudFlowEvent *ev;
    cf_splunk_config_t s;
    char *line;
    FILE *out;

    snprintf(pb_path, sizeof(pb_path), "tests/fixtures/%s.pb", pb_name);
    snprintf(golden_path, sizeof(golden_path), "tests/golden/%s.json", golden_name);
    snprintf(out_path, sizeof(out_path), "build/golden_out_%s.json", golden_name);

    buf = read_file(pb_path, &len);
    CU_ASSERT_PTR_NOT_NULL_FATAL(buf);

    ev = cloudflow__v1__cloud_flow_event__unpack(NULL, len, buf);
    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);

    make_config(&s, include_raw);
    line = cf_transform_render_hec_line(ev, stream, &s);
    CU_ASSERT_PTR_NOT_NULL_FATAL(line);

    out = fopen(out_path, "wb");
    CU_ASSERT_PTR_NOT_NULL_FATAL(out);
    fprintf(out, "%s\n", line);
    fclose(out);

    CU_ASSERT_TRUE(json_equal(out_path, golden_path));

    free(line);
    cloudflow__v1__cloud_flow_event__free_unpacked(ev, NULL);
    free(buf);
}

static void test_dhcpv4_discover(void)
{
    run_case("dhcpv4_discover", "dhcpv4_discover", "cloudflow:v1:wire:dhcpv4", 0);
}

static void test_dhcpv4_raw_stripped(void)
{
    /* Golden was produced with include_raw_payload=false; the .pb carries the
     * raw payload, which the transform must strip. */
    run_case("dhcpv4_discover_raw_payload_stripped", "dhcpv4_discover_raw_payload_stripped",
             "cloudflow:v1:wire:dhcpv4", 0);
}

static void test_dhcpv6_solicit(void)
{
    run_case("dhcpv6_solicit", "dhcpv6_solicit", "cloudflow:v1:wire:dhcpv6", 0);
}

static void test_dns_transaction(void)
{
    /* A fully-correlated client-facing DNS transaction (dns_transaction oneof):
     * both packets, a decoded question + answer, role, rtt, client/server ip.
     * source_type "dns" maps to sourcetype cloudflow:dns. */
    run_case("dns_transaction", "dns_transaction", "cloudflow:v1:wire:dns", 0);
}

static void test_raw_payload_kept_when_configured(void)
{
    /* With include_raw_payload=1 the field must appear. */
    uint8_t *buf;
    size_t len = 0;
    Cloudflow__V1__CloudFlowEvent *ev;
    cf_splunk_config_t s;
    char *line;

    buf = read_file("tests/fixtures/dhcpv4_discover_raw_payload_stripped.pb", &len);
    CU_ASSERT_PTR_NOT_NULL_FATAL(buf);
    ev = cloudflow__v1__cloud_flow_event__unpack(NULL, len, buf);
    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);
    make_config(&s, 1);
    line = cf_transform_render_hec_line(ev, "cloudflow:v1:wire:dhcpv4", &s);
    CU_ASSERT_PTR_NOT_NULL_FATAL(line);
    CU_ASSERT_PTR_NOT_NULL(strstr(line, "raw_dhcp_payload"));
    free(line);
    cloudflow__v1__cloud_flow_event__free_unpacked(ev, NULL);
    free(buf);
}

int main(void)
{
    CU_pSuite suite;
    unsigned int failed;

    if (CU_initialize_registry() != CUE_SUCCESS)
        return (int)CU_get_error();

    suite = CU_add_suite("transform_golden", NULL, NULL);
    if (!suite ||
        !CU_add_test(suite, "dhcpv4 discover golden", test_dhcpv4_discover) ||
        !CU_add_test(suite, "dhcpv4 raw payload stripped golden", test_dhcpv4_raw_stripped) ||
        !CU_add_test(suite, "dhcpv6 solicit golden", test_dhcpv6_solicit) ||
        !CU_add_test(suite, "dns transaction golden", test_dns_transaction) ||
        !CU_add_test(suite, "raw payload kept when configured", test_raw_payload_kept_when_configured)) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    failed = CU_get_number_of_tests_failed();
    CU_cleanup_registry();
    return failed > 0 ? 1 : 0;
}
