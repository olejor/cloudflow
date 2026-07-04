/* CUnit tests for the WP-DNS10 DNS sampling / emit-policy engine
 * (src/sampling.c), implementing decision DNS-D8 in docs/dns-source.md. Pure:
 * no sockets, no packets, no RNG -- every case is a hand-built policy plus a
 * hand-built facts struct. Follows the registry/main pattern of
 * tests/unit/cf_dns_test.c and tests/leg_classify_test.c.
 */

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include <stdint.h>

#include "sampling.h"

/* A routine A/AAAA NOERROR OBSERVED fact with a caller-chosen sample key. */
static cf_dns_emit_facts_t routine_fact(uint32_t qtype, uint64_t key)
{
    cf_dns_emit_facts_t f;
    f.outcome = CF_DNS_TXN_OBSERVED;
    f.rcode = CF_DNS_RCODE_NOERROR;
    f.qtype = qtype;
    f.has_response = 1;
    f.sample_key = key;
    return f;
}

/* ---- ALL mode: emit every combination -------------------------------------- */

static void test_all_mode_emits_everything(void)
{
    cf_dns_emit_policy_t pol = { CF_DNS_EMIT_ALL, 10 };
    cf_dns_emit_facts_t f;

    /* routine A NOERROR observed -> emit even though a denom is set */
    f = routine_fact(CF_DNS_QTYPE_A, 12345);
    CU_ASSERT_EQUAL(cf_dns_emit_decide(&pol, &f), 1);

    /* SERVFAIL -> emit */
    f = routine_fact(CF_DNS_QTYPE_A, 12345);
    f.rcode = 2;
    CU_ASSERT_EQUAL(cf_dns_emit_decide(&pol, &f), 1);

    /* unanswered -> emit */
    f = routine_fact(CF_DNS_QTYPE_A, 12345);
    f.outcome = CF_DNS_TXN_UNANSWERED;
    f.has_response = 0;
    CU_ASSERT_EQUAL(cf_dns_emit_decide(&pol, &f), 1);

    /* unmatched response -> emit */
    f = routine_fact(CF_DNS_QTYPE_A, 12345);
    f.outcome = CF_DNS_TXN_UNMATCHED;
    CU_ASSERT_EQUAL(cf_dns_emit_decide(&pol, &f), 1);

    /* NULL policy is treated as ALL -> emit */
    f = routine_fact(CF_DNS_QTYPE_A, 12345);
    CU_ASSERT_EQUAL(cf_dns_emit_decide(NULL, &f), 1);
}

/* ---- PREDICATE mode: always-emit predicates -------------------------------- */

static void test_predicate_routine_denom1_always_emit(void)
{
    /* denom 1 means keep-all: a routine NOERROR A must always emit. */
    cf_dns_emit_policy_t pol = { CF_DNS_EMIT_PREDICATE, 1 };
    uint64_t k;
    for (k = 0; k < 1000; k++) {
        cf_dns_emit_facts_t f = routine_fact(CF_DNS_QTYPE_A, k);
        CU_ASSERT_EQUAL(cf_dns_emit_decide(&pol, &f), 1);
    }
}

static void test_predicate_denom0_always_emit(void)
{
    /* denom 0 also means keep-all. */
    cf_dns_emit_policy_t pol = { CF_DNS_EMIT_PREDICATE, 0 };
    uint64_t k;
    for (k = 0; k < 1000; k++) {
        cf_dns_emit_facts_t f = routine_fact(CF_DNS_QTYPE_AAAA, k);
        CU_ASSERT_EQUAL(cf_dns_emit_decide(&pol, &f), 1);
    }
}

static void test_predicate_unanswered_unmatched_always_emit(void)
{
    /* Even with aggressive sampling, loss/anomaly outcomes are never dropped. */
    cf_dns_emit_policy_t pol = { CF_DNS_EMIT_PREDICATE, 1000000 };
    uint64_t k;
    for (k = 0; k < 500; k++) {
        cf_dns_emit_facts_t f = routine_fact(CF_DNS_QTYPE_A, k);
        f.outcome = CF_DNS_TXN_UNANSWERED;
        f.has_response = 0;
        CU_ASSERT_EQUAL(cf_dns_emit_decide(&pol, &f), 1);

        f = routine_fact(CF_DNS_QTYPE_A, k);
        f.outcome = CF_DNS_TXN_UNMATCHED;
        CU_ASSERT_EQUAL(cf_dns_emit_decide(&pol, &f), 1);
    }
}

static void test_predicate_error_rcode_always_emit(void)
{
    /* SERVFAIL (rcode 2) on a routine A must always emit despite sampling. */
    cf_dns_emit_policy_t pol = { CF_DNS_EMIT_PREDICATE, 1000000 };
    uint64_t k;
    for (k = 0; k < 500; k++) {
        cf_dns_emit_facts_t f = routine_fact(CF_DNS_QTYPE_A, k);
        f.rcode = 2; /* SERVFAIL */
        CU_ASSERT_EQUAL(cf_dns_emit_decide(&pol, &f), 1);
    }
}

static void test_predicate_unusual_qtype_always_emit(void)
{
    /* MX (15) NOERROR observed is a non-routine qtype -> always emit. */
    cf_dns_emit_policy_t pol = { CF_DNS_EMIT_PREDICATE, 1000000 };
    uint64_t k;
    for (k = 0; k < 500; k++) {
        cf_dns_emit_facts_t f = routine_fact(15 /* MX */, k);
        CU_ASSERT_EQUAL(cf_dns_emit_decide(&pol, &f), 1);
    }
}

static void test_predicate_null_facts_drop(void)
{
    /* PREDICATE mode with no facts: nothing to emit. */
    cf_dns_emit_policy_t pol = { CF_DNS_EMIT_PREDICATE, 10 };
    CU_ASSERT_EQUAL(cf_dns_emit_decide(&pol, NULL), 0);
}

/* ---- PREDICATE mode: sampling correctness ---------------------------------- */

static void test_predicate_aaaa_routine_gets_sampled(void)
{
    /* Routine AAAA NOERROR is eligible for sampling: over a sweep, SOME keys
     * are kept and SOME are dropped (it is not a degenerate all-or-nothing). */
    cf_dns_emit_policy_t pol = { CF_DNS_EMIT_PREDICATE, 10 };
    uint64_t k;
    int kept = 0, dropped = 0;
    for (k = 0; k < 2000; k++) {
        cf_dns_emit_facts_t f = routine_fact(CF_DNS_QTYPE_AAAA, k);
        if (cf_dns_emit_decide(&pol, &f))
            kept++;
        else
            dropped++;
    }
    CU_ASSERT_TRUE(kept > 0);
    CU_ASSERT_TRUE(dropped > 0);
}

static void test_sampling_fraction_approx_and_deterministic(void)
{
    /* With denom 10 over a large sweep of distinct keys, the kept fraction is
     * ~1/10; and the SAME key always yields the SAME verdict. */
    cf_dns_emit_policy_t pol = { CF_DNS_EMIT_PREDICATE, 10 };
    const uint64_t N = 100000;
    uint64_t k;
    uint64_t kept = 0;
    double fraction;

    for (k = 0; k < N; k++) {
        cf_dns_emit_facts_t f = routine_fact(CF_DNS_QTYPE_A, k);
        int d1 = cf_dns_emit_decide(&pol, &f);
        int d2 = cf_dns_emit_decide(&pol, &f);
        /* determinism: repeat call on identical facts is identical */
        CU_ASSERT_EQUAL(d1, d2);
        if (d1)
            kept++;
    }

    fraction = (double)kept / (double)N;
    /* Expect ~0.10; allow a generous tolerance for hash variance. */
    CU_ASSERT_TRUE(fraction > 0.085 && fraction < 0.115);
}

static void test_sampling_same_key_same_decision(void)
{
    /* A specific key gives one stable verdict across the qtypes it applies to
     * and across repeated calls -- determinism at the individual-key level. */
    cf_dns_emit_policy_t pol = { CF_DNS_EMIT_PREDICATE, 7 };
    uint64_t k;
    for (k = 1; k < 200; k++) {
        cf_dns_emit_facts_t a = routine_fact(CF_DNS_QTYPE_A, k * 2654435761ULL);
        cf_dns_emit_facts_t b = routine_fact(CF_DNS_QTYPE_A, k * 2654435761ULL);
        CU_ASSERT_EQUAL(cf_dns_emit_decide(&pol, &a),
                        cf_dns_emit_decide(&pol, &b));
    }
}

/* ---- driver --------------------------------------------------------------- */

int main(void)
{
    CU_pSuite suite;
    unsigned int failed;

    if (CU_initialize_registry() != CUE_SUCCESS)
        return (int)CU_get_error();

    suite = CU_add_suite("sampling", NULL, NULL);
    if (!suite) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    if (!CU_add_test(suite, "ALL mode emits every combination", test_all_mode_emits_everything) ||
        !CU_add_test(suite, "PREDICATE routine denom 1 always emits", test_predicate_routine_denom1_always_emit) ||
        !CU_add_test(suite, "PREDICATE denom 0 always emits", test_predicate_denom0_always_emit) ||
        !CU_add_test(suite, "PREDICATE unanswered/unmatched always emit", test_predicate_unanswered_unmatched_always_emit) ||
        !CU_add_test(suite, "PREDICATE error rcode always emits", test_predicate_error_rcode_always_emit) ||
        !CU_add_test(suite, "PREDICATE unusual qtype always emits", test_predicate_unusual_qtype_always_emit) ||
        !CU_add_test(suite, "PREDICATE NULL facts drop", test_predicate_null_facts_drop) ||
        !CU_add_test(suite, "PREDICATE routine AAAA gets sampled", test_predicate_aaaa_routine_gets_sampled) ||
        !CU_add_test(suite, "PREDICATE sampling fraction ~1/N + deterministic", test_sampling_fraction_approx_and_deterministic) ||
        !CU_add_test(suite, "PREDICATE same key same decision", test_sampling_same_key_same_decision)) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();

    failed = CU_get_number_of_tests_failed();
    CU_cleanup_registry();
    return failed > 0 ? 1 : 0;
}
