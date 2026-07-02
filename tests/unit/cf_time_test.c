/* Basic cf_time sanity checks: cf_now_unix_nano() looks like a plausible
 * wall-clock time, cf_now_mono_nano() is monotonically non-decreasing, and
 * cf_sleep_ns() actually sleeps for roughly the requested duration. */

#include <CUnit/CUnit.h>

#include "cf_core_test.h"
#include "cf_time.h"

/* 2020-01-01T00:00:00Z in unix nanoseconds; a sane lower bound for "now" on
 * any machine this test will actually run on. */
#define CF_TIME_SANE_LOWER_BOUND_NS (1577836800LL * 1000000000LL)

static void test_unix_nano_plausible(void)
{
    int64_t now = cf_now_unix_nano();

    CU_ASSERT_TRUE(now > CF_TIME_SANE_LOWER_BOUND_NS);
}

static void test_mono_nano_monotonic(void)
{
    int64_t t1 = cf_now_mono_nano();
    int64_t t2;
    volatile int i;

    /* Cheap busy-work so t2 has a chance to differ from t1 even on a
     * coarse clock; monotonicity must hold regardless. */
    for (i = 0; i < 1000; i++)
        ;

    t2 = cf_now_mono_nano();

    CU_ASSERT_TRUE(t2 >= t1);
}

static void test_sleep_ns_sleeps_for_at_least_requested(void)
{
    const int64_t sleep_duration_ns = 5 * 1000 * 1000; /* 5ms */
    int64_t before = cf_now_mono_nano();
    int64_t after;
    int64_t elapsed;

    cf_sleep_ns(sleep_duration_ns);

    after = cf_now_mono_nano();
    elapsed = after - before;

    CU_ASSERT_TRUE(elapsed >= sleep_duration_ns);
}

static void test_sleep_ns_zero_is_noop(void)
{
    /* Must not block or crash. */
    cf_sleep_ns(0);
    cf_sleep_ns(-1);

    CU_ASSERT_TRUE(1);
}

int cf_time_register_suite(void)
{
    CU_pSuite suite = CU_add_suite("cf_time", NULL, NULL);

    if (!suite)
        return -1;

    if (!CU_add_test(suite, "cf_now_unix_nano is plausible", test_unix_nano_plausible))
        return -1;
    if (!CU_add_test(suite, "cf_now_mono_nano is monotonic", test_mono_nano_monotonic))
        return -1;
    if (!CU_add_test(suite, "cf_sleep_ns sleeps >= requested duration", test_sleep_ns_sleeps_for_at_least_requested))
        return -1;
    if (!CU_add_test(suite, "cf_sleep_ns(0)/negative is a no-op", test_sleep_ns_zero_is_noop))
        return -1;

    return 0;
}
