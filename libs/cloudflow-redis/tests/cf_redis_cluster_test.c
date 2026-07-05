/* Unit tests for the pure parts of the cluster router: the -MOVED / -ASK
 * redirect parser. The live routing (CLUSTER SLOTS topology, node pool,
 * redirect-follow) needs a real cluster and is exercised by the harness's
 * cluster leg in CI; here we pin the string parsing that decides where a
 * redirected command goes. */

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>
#include <string.h>

#include "cf_redis_cluster.h"

static void test_moved(void)
{
    int slot = -1, port = -1;
    char host[256];
    int kind = cf_redis_parse_redirect("MOVED 3999 127.0.0.1:6381", &slot, host, sizeof(host), &port);

    CU_ASSERT_EQUAL(kind, CF_REDIS_REDIRECT_MOVED);
    CU_ASSERT_EQUAL(slot, 3999);
    CU_ASSERT_STRING_EQUAL(host, "127.0.0.1");
    CU_ASSERT_EQUAL(port, 6381);
}

static void test_ask(void)
{
    int slot = -1, port = -1;
    char host[256];
    int kind = cf_redis_parse_redirect("ASK 7000 10.0.0.5:7002", &slot, host, sizeof(host), &port);

    CU_ASSERT_EQUAL(kind, CF_REDIS_REDIRECT_ASK);
    CU_ASSERT_EQUAL(slot, 7000);
    CU_ASSERT_STRING_EQUAL(host, "10.0.0.5");
    CU_ASSERT_EQUAL(port, 7002);
}

static void test_not_a_redirect(void)
{
    int slot = -1, port = -1;
    char host[256];

    /* A genuine error reply must be classified NONE so callers surface it. */
    CU_ASSERT_EQUAL(cf_redis_parse_redirect("WRONGTYPE Operation against a key",
                                            &slot, host, sizeof(host), &port),
                    CF_REDIS_REDIRECT_NONE);
    CU_ASSERT_EQUAL(cf_redis_parse_redirect("CROSSSLOT Keys don't hash to the same slot",
                                            &slot, host, sizeof(host), &port),
                    CF_REDIS_REDIRECT_NONE);
    CU_ASSERT_EQUAL(cf_redis_parse_redirect(NULL, &slot, host, sizeof(host), &port),
                    CF_REDIS_REDIRECT_NONE);
    /* "MOVED"-prefixed word that is not the redirect form. */
    CU_ASSERT_EQUAL(cf_redis_parse_redirect("MOVEDNONSENSE", &slot, host, sizeof(host), &port),
                    CF_REDIS_REDIRECT_NONE);
}

static void test_malformed(void)
{
    int slot = -1, port = -1;
    char host[256];

    /* Missing port. */
    CU_ASSERT_EQUAL(cf_redis_parse_redirect("MOVED 10 host-no-port", &slot, host, sizeof(host), &port),
                    CF_REDIS_REDIRECT_NONE);
    /* Non-numeric slot. */
    CU_ASSERT_EQUAL(cf_redis_parse_redirect("MOVED x 1.2.3.4:6379", &slot, host, sizeof(host), &port),
                    CF_REDIS_REDIRECT_NONE);
    /* Port out of range. */
    CU_ASSERT_EQUAL(cf_redis_parse_redirect("MOVED 10 1.2.3.4:70000", &slot, host, sizeof(host), &port),
                    CF_REDIS_REDIRECT_NONE);
    /* Host too long for the buffer -> rejected, no overflow. */
    {
        char tiny[4];
        CU_ASSERT_EQUAL(cf_redis_parse_redirect("MOVED 10 longhost:6379", &slot, tiny, sizeof(tiny), &port),
                        CF_REDIS_REDIRECT_NONE);
    }
}

int main(void)
{
    CU_pSuite s;
    unsigned int failed;

    if (CU_initialize_registry() != CUE_SUCCESS)
        return (int)CU_get_error();
    s = CU_add_suite("cf_redis_cluster (redirect parse)", NULL, NULL);
    if (!s ||
        !CU_add_test(s, "MOVED", test_moved) ||
        !CU_add_test(s, "ASK", test_ask) ||
        !CU_add_test(s, "non-redirect errors classified NONE", test_not_a_redirect) ||
        !CU_add_test(s, "malformed redirects rejected", test_malformed)) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    failed = CU_get_number_of_tests_failed();
    CU_cleanup_registry();
    return failed > 0 ? 1 : 0;
}
