/* Acceptance tests for cf_sync (the process-wide shutdown flag). Part of the
 * cf_core_test binary, registered LAST: cf_stop_notify() sets a file-scoped
 * process-global flag with no reset API (by design -- shutdown is one-way), so
 * once this suite trips the flag it stays tripped for the rest of the binary.
 * No other suite in cf_core_test reads the flag, and each test binary is its
 * own process, so this pollutes nothing. */

#include <CUnit/CUnit.h>

#include "cf_core_test.h"
#include "cf_sync.h"

/* Must run before any notify: the flag starts clear. */
static void test_sync_initially_clear(void)
{
    CU_ASSERT_EQUAL(cf_stop_notified(), 0);
}

/* A plain shutdown request (code 0) trips the flag; cf_stop_notified() then
 * stays non-zero, and repeat requests are idempotent (never clear it). */
static void test_sync_notify_sets_flag(void)
{
    cf_stop_notify(0);
    CU_ASSERT_NOT_EQUAL(cf_stop_notified(), 0);

    /* Idempotent: a second notify (with a non-zero code) keeps it set. */
    cf_stop_notify(2);
    CU_ASSERT_NOT_EQUAL(cf_stop_notified(), 0);
}

int cf_sync_register_suite(void)
{
    CU_pSuite suite = CU_add_suite("cf_sync (stop flag)", NULL, NULL);

    if (!suite)
        return -1;

    /* Order matters: "initially clear" must precede "notify sets flag". */
    if (!CU_add_test(suite, "flag starts clear", test_sync_initially_clear))
        return -1;
    if (!CU_add_test(suite, "notify sets flag, idempotent", test_sync_notify_sets_flag))
        return -1;

    return 0;
}
