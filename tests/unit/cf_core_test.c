/* CUnit driver for the WP-03 cloudflow-core acceptance tests. Individual
 * suites live in cf_sha256_test.c, cf_event_id_test.c, cf_log_test.c, and
 * cf_time_test.c; each exposes a `cf_*_register_suite()` function declared
 * in cf_core_test.h. */

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include "cf_core_test.h"

int main(void)
{
    unsigned int failed;

    if (CU_initialize_registry() != CUE_SUCCESS)
        return (int)CU_get_error();

    if (cf_sha256_register_suite() != 0 ||
        cf_event_id_register_suite() != 0 ||
        cf_log_register_suite() != 0 ||
        cf_time_register_suite() != 0) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();

    failed = CU_get_number_of_tests_failed();

    CU_cleanup_registry();

    return failed > 0 ? 1 : 0;
}
