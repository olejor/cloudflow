/* CUnit acceptance tests for the WP-DNS04 correlation stage
 * (src/correlation.c). Standalone binary (build/correlation_test), following
 * the one-binary-per-WP pattern (tests/unit/Makefile, cf_dns_test.c).
 *
 * The correlator is fully decoupled from protobuf, so these tests drive the
 * bounded pending table directly with hand-built DNS-D6 keys and
 * heap-allocated fake contexts (plain malloc'd ints). The emit callback frees
 * every context it is handed and counts the frees; each test asserts that the
 * number of contexts freed equals the number allocated -- i.e. every context
 * is released EXACTLY once (no leak, no double free). The ASan+UBSan variant
 * turns any violation of the ownership contract into a hard sanitizer error.
 */

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "correlation.h"

/* ---- fake-context bookkeeping -------------------------------------------- */

static int g_allocs; /* contexts malloc'd since the last reset */

static int *mk_ctx(int v)
{
    int *p = malloc(sizeof(int));

    CU_ASSERT_PTR_NOT_NULL_FATAL(p);
    *p = v;
    g_allocs++;
    return p;
}

typedef struct {
    int                  observed, unanswered, unmatched;
    int                  free_count;
    int64_t              last_rtt;
    int                  last_rtt_valid;
    int                  last_query_val;    /* *query_ctx of the last emit, or -1 */
    int                  last_response_val; /* *response_ctx of the last emit, or -1 */
    cf_dns_txn_key_t     last_key;
} harness_t;

static void emit_cb(void *user, cf_dns_txn_outcome_t outcome, void *query_ctx,
                    void *response_ctx, int64_t rtt_nanos, int rtt_valid,
                    const cf_dns_txn_key_t *key)
{
    harness_t *h = user;

    switch (outcome) {
    case CF_DNS_TXN_OBSERVED:
        h->observed++;
        CU_ASSERT_PTR_NOT_NULL(query_ctx);
        CU_ASSERT_PTR_NOT_NULL(response_ctx);
        break;
    case CF_DNS_TXN_UNANSWERED:
        h->unanswered++;
        CU_ASSERT_PTR_NOT_NULL(query_ctx);
        CU_ASSERT_PTR_NULL(response_ctx);
        break;
    case CF_DNS_TXN_UNMATCHED:
        h->unmatched++;
        CU_ASSERT_PTR_NULL(query_ctx);
        CU_ASSERT_PTR_NOT_NULL(response_ctx);
        break;
    }

    CU_ASSERT_PTR_NOT_NULL_FATAL(key);
    h->last_key = *key;
    h->last_rtt = rtt_nanos;
    h->last_rtt_valid = rtt_valid;
    h->last_query_val = query_ctx ? *(int *)query_ctx : -1;
    h->last_response_val = response_ctx ? *(int *)response_ctx : -1;

    /* The caller owns freeing the contexts inside the emit callback. */
    if (query_ctx) {
        free(query_ctx);
        h->free_count++;
    }
    if (response_ctx) {
        free(response_ctx);
        h->free_count++;
    }
}

/* ---- key builder --------------------------------------------------------- */

static cf_dns_txn_key_t mkkey(uint16_t dns_id, const char *qname, uint16_t qtype,
                              uint16_t client_port)
{
    cf_dns_txn_key_t k;
    size_t           n = strlen(qname);

    memset(&k, 0, sizeof(k));
    k.transport = 0;       /* udp */
    k.local_is_server = 1;
    k.ip_version = 4;
    k.client_ip[0] = 192; k.client_ip[1] = 0; k.client_ip[2] = 2; k.client_ip[3] = 1;
    k.server_ip[0] = 192; k.server_ip[1] = 0; k.server_ip[2] = 2; k.server_ip[3] = 53;
    k.client_port = client_port;
    k.server_port = 53;
    k.dns_id = dns_id;
    k.qtype = qtype;
    k.qclass = 1;
    if (n > sizeof(k.qname_canonical))
        n = sizeof(k.qname_canonical);
    memcpy(k.qname_canonical, qname, n);
    k.qname_len = (uint16_t)n;
    return k;
}

/* Standard-ish knobs for most tests. */
#define TIMEOUT_NS (5000LL * 1000 * 1000) /* 5s, the DNS-D8 default */

static cf_dns_correlator_t *new_corr(harness_t *h, size_t cap, int on_full)
{
    cf_dns_correlator_config_t cfg;
    cf_dns_correlator_t       *c;

    memset(h, 0, sizeof(*h));
    g_allocs = 0;

    cfg.capacity = cap;
    cfg.query_timeout_nanos = TIMEOUT_NS;
    cfg.on_table_full = on_full;

    c = cf_dns_correlator_new(&cfg, emit_cb, h);
    CU_ASSERT_PTR_NOT_NULL_FATAL(c);
    return c;
}

/* Free the correlator (drains remaining pending) and assert the ownership
 * contract held: every allocated context was released exactly once. */
static void finish(cf_dns_correlator_t *c, harness_t *h)
{
    cf_dns_correlator_free(c);
    CU_ASSERT_EQUAL(h->free_count, g_allocs);
}

static size_t depth(cf_dns_correlator_t *c)
{
    cf_dns_correlator_stats_t s;

    cf_dns_correlator_stats(c, &s);
    return s.pending_depth;
}

/* ---- tests --------------------------------------------------------------- */

static void test_match_observed(void)
{
    harness_t h;
    cf_dns_correlator_t *c = new_corr(&h, 16, CF_DNS_ON_FULL_DROP_NEWEST);
    cf_dns_txn_key_t k = mkkey(0x1234, "example.com", 1, 40000);
    cf_dns_correlator_stats_t s;

    cf_dns_correlator_on_query(c, &k, 1000, mk_ctx(1));
    CU_ASSERT_EQUAL(depth(c), 1);

    cf_dns_correlator_on_response(c, &k, 1500, mk_ctx(2));

    CU_ASSERT_EQUAL(h.observed, 1);
    CU_ASSERT_EQUAL(h.unanswered, 0);
    CU_ASSERT_EQUAL(h.unmatched, 0);
    CU_ASSERT_EQUAL(h.last_rtt, 500);
    CU_ASSERT_EQUAL(h.last_rtt_valid, 1);
    CU_ASSERT_EQUAL(h.last_query_val, 1);
    CU_ASSERT_EQUAL(h.last_response_val, 2);
    CU_ASSERT_EQUAL(depth(c), 0);

    cf_dns_correlator_stats(c, &s);
    CU_ASSERT_EQUAL(s.transactions_observed, 1);
    CU_ASSERT_EQUAL(s.rtt_invalid, 0);

    finish(c, &h);
}

static void test_response_unmatched(void)
{
    harness_t h;
    cf_dns_correlator_t *c = new_corr(&h, 16, CF_DNS_ON_FULL_DROP_NEWEST);
    cf_dns_txn_key_t k = mkkey(0x2222, "nowhere.example", 1, 40001);
    cf_dns_correlator_stats_t s;

    cf_dns_correlator_on_response(c, &k, 2000, mk_ctx(7));

    CU_ASSERT_EQUAL(h.unmatched, 1);
    CU_ASSERT_EQUAL(h.observed, 0);
    CU_ASSERT_EQUAL(h.last_response_val, 7);
    CU_ASSERT_EQUAL(depth(c), 0);

    cf_dns_correlator_stats(c, &s);
    CU_ASSERT_EQUAL(s.response_unmatched, 1);

    finish(c, &h);
}

static void test_timeout_then_late_response(void)
{
    harness_t h;
    cf_dns_correlator_t *c = new_corr(&h, 16, CF_DNS_ON_FULL_DROP_NEWEST);
    cf_dns_txn_key_t k = mkkey(0x3333, "slow.example", 28, 40002);
    cf_dns_correlator_stats_t s;

    cf_dns_correlator_on_query(c, &k, 1000, mk_ctx(11));
    CU_ASSERT_EQUAL(depth(c), 1);

    /* now well past the timeout -> evicted UNANSWERED. */
    cf_dns_correlator_tick(c, 1000 + TIMEOUT_NS + 1);
    CU_ASSERT_EQUAL(h.unanswered, 1);
    CU_ASSERT_EQUAL(depth(c), 0);

    cf_dns_correlator_stats(c, &s);
    CU_ASSERT_EQUAL(s.query_unanswered, 1);

    /* a response arriving after eviction has no pending query. */
    cf_dns_correlator_on_response(c, &k, 1000 + TIMEOUT_NS + 100, mk_ctx(12));
    CU_ASSERT_EQUAL(h.unmatched, 1);
    CU_ASSERT_EQUAL(h.observed, 0);

    cf_dns_correlator_stats(c, &s);
    CU_ASSERT_EQUAL(s.response_unmatched, 1);

    finish(c, &h);
}

static void test_same_key_collision(void)
{
    harness_t h;
    cf_dns_correlator_t *c = new_corr(&h, 16, CF_DNS_ON_FULL_DROP_NEWEST);
    cf_dns_txn_key_t k = mkkey(0x4444, "dup.example", 1, 40003);
    cf_dns_correlator_stats_t s;

    cf_dns_correlator_on_query(c, &k, 1000, mk_ctx(21));  /* older */
    cf_dns_correlator_on_query(c, &k, 1100, mk_ctx(22));  /* same key -> evicts older */

    CU_ASSERT_EQUAL(h.unanswered, 1);          /* the first one */
    CU_ASSERT_EQUAL(h.last_query_val, 21);
    CU_ASSERT_EQUAL(depth(c), 1);

    cf_dns_correlator_stats(c, &s);
    CU_ASSERT_EQUAL(s.pending_evicted_collision, 1);

    /* the surviving (second) query matches. */
    cf_dns_correlator_on_response(c, &k, 1200, mk_ctx(23));
    CU_ASSERT_EQUAL(h.observed, 1);
    CU_ASSERT_EQUAL(h.last_query_val, 22);
    CU_ASSERT_EQUAL(h.last_rtt, 100);          /* from the second query's time */
    CU_ASSERT_EQUAL(depth(c), 0);

    finish(c, &h);
}

static void test_table_full_drop_newest(void)
{
    harness_t h;
    cf_dns_correlator_t *c = new_corr(&h, 2, CF_DNS_ON_FULL_DROP_NEWEST);
    cf_dns_txn_key_t k0 = mkkey(1, "a.example", 1, 40010);
    cf_dns_txn_key_t k1 = mkkey(2, "b.example", 1, 40011);
    cf_dns_txn_key_t k2 = mkkey(3, "c.example", 1, 40012);
    cf_dns_correlator_stats_t s;

    cf_dns_correlator_on_query(c, &k0, 1000, mk_ctx(30));
    cf_dns_correlator_on_query(c, &k1, 1100, mk_ctx(31));
    /* table full (cap 2): drop_newest drops THIS query immediately. */
    cf_dns_correlator_on_query(c, &k2, 1200, mk_ctx(32));

    CU_ASSERT_EQUAL(h.unanswered, 1);          /* the just-arrived k2 */
    CU_ASSERT_EQUAL(h.last_query_val, 32);
    CU_ASSERT_EQUAL(depth(c), 2);

    cf_dns_correlator_stats(c, &s);
    CU_ASSERT_EQUAL(s.pending_drop, 1);

    /* k0 and k1 are still pending; k2 was dropped. */
    cf_dns_correlator_on_response(c, &k2, 1300, mk_ctx(33)); /* unmatched */
    cf_dns_correlator_on_response(c, &k0, 1300, mk_ctx(34)); /* observed */
    cf_dns_correlator_on_response(c, &k1, 1300, mk_ctx(35)); /* observed */

    CU_ASSERT_EQUAL(h.unmatched, 1);
    CU_ASSERT_EQUAL(h.observed, 2);
    CU_ASSERT_EQUAL(depth(c), 0);

    finish(c, &h);
}

static void test_table_full_drop_oldest(void)
{
    harness_t h;
    cf_dns_correlator_t *c = new_corr(&h, 2, CF_DNS_ON_FULL_DROP_OLDEST);
    cf_dns_txn_key_t k0 = mkkey(1, "a.example", 1, 40020);
    cf_dns_txn_key_t k1 = mkkey(2, "b.example", 1, 40021);
    cf_dns_txn_key_t k2 = mkkey(3, "c.example", 1, 40022);
    cf_dns_correlator_stats_t s;

    cf_dns_correlator_on_query(c, &k0, 1000, mk_ctx(40)); /* oldest */
    cf_dns_correlator_on_query(c, &k1, 1100, mk_ctx(41));
    /* table full: drop_oldest evicts k0 to make room for k2. */
    cf_dns_correlator_on_query(c, &k2, 1200, mk_ctx(42));

    CU_ASSERT_EQUAL(h.unanswered, 1);          /* the evicted oldest k0 */
    CU_ASSERT_EQUAL(h.last_query_val, 40);
    CU_ASSERT_EQUAL(depth(c), 2);

    cf_dns_correlator_stats(c, &s);
    CU_ASSERT_EQUAL(s.pending_drop, 1);

    /* k0 was evicted; k1 and k2 are pending. */
    cf_dns_correlator_on_response(c, &k0, 1300, mk_ctx(43)); /* unmatched */
    cf_dns_correlator_on_response(c, &k1, 1300, mk_ctx(44)); /* observed */
    cf_dns_correlator_on_response(c, &k2, 1300, mk_ctx(45)); /* observed */

    CU_ASSERT_EQUAL(h.unmatched, 1);
    CU_ASSERT_EQUAL(h.observed, 2);
    CU_ASSERT_EQUAL(depth(c), 0);

    finish(c, &h);
}

static void test_rtt_invalid(void)
{
    harness_t h;
    cf_dns_correlator_t *c = new_corr(&h, 16, CF_DNS_ON_FULL_DROP_NEWEST);
    cf_dns_txn_key_t kn = mkkey(0x5151, "neg.example", 1, 40030);
    cf_dns_txn_key_t kb = mkkey(0x5252, "big.example", 1, 40031);
    cf_dns_correlator_stats_t s;

    /* negative RTT (response observed before query -- reordering/clock skew). */
    cf_dns_correlator_on_query(c, &kn, 2000, mk_ctx(51));
    cf_dns_correlator_on_response(c, &kn, 1000, mk_ctx(52));
    CU_ASSERT_EQUAL(h.observed, 1);
    CU_ASSERT_EQUAL(h.last_rtt_valid, 0);
    CU_ASSERT_EQUAL(h.last_rtt, -1000);

    /* implausibly large RTT (> query_timeout). */
    cf_dns_correlator_on_query(c, &kb, 1000, mk_ctx(53));
    cf_dns_correlator_on_response(c, &kb, 1000 + TIMEOUT_NS + 5, mk_ctx(54));
    CU_ASSERT_EQUAL(h.observed, 2);
    CU_ASSERT_EQUAL(h.last_rtt_valid, 0);

    cf_dns_correlator_stats(c, &s);
    CU_ASSERT_EQUAL(s.rtt_invalid, 2);
    CU_ASSERT_EQUAL(s.transactions_observed, 2);

    finish(c, &h);
}

static void test_free_drains_pending(void)
{
    harness_t h;
    cf_dns_correlator_t *c = new_corr(&h, 16, CF_DNS_ON_FULL_DROP_NEWEST);
    int i;

    for (i = 0; i < 5; i++) {
        cf_dns_txn_key_t k = mkkey((uint16_t)(0x6000 + i), "drain.example", 1,
                                   (uint16_t)(40040 + i));
        cf_dns_correlator_on_query(c, &k, 1000 + i, mk_ctx(60 + i));
    }
    CU_ASSERT_EQUAL(depth(c), 5);

    /* free() must drain all 5 as UNANSWERED so nothing leaks. */
    finish(c, &h); /* frees c, then asserts free_count == g_allocs */
    CU_ASSERT_EQUAL(h.unanswered, 5);
    CU_ASSERT_EQUAL(h.free_count, 5);
}

static void test_key_isolation(void)
{
    harness_t h;
    cf_dns_correlator_t *c = new_corr(&h, 16, CF_DNS_ON_FULL_DROP_NEWEST);
    cf_dns_txn_key_t base = mkkey(0x7777, "iso.example", 1, 40050);
    cf_dns_txn_key_t d_id = mkkey(0x7778, "iso.example", 1, 40050);   /* dns_id */
    cf_dns_txn_key_t d_name = mkkey(0x7777, "iso2.example", 1, 40050); /* qname */
    cf_dns_txn_key_t d_type = mkkey(0x7777, "iso.example", 28, 40050); /* qtype */
    cf_dns_txn_key_t d_port = mkkey(0x7777, "iso.example", 1, 40051);  /* client_port */

    cf_dns_correlator_on_query(c, &base, 1000, mk_ctx(70));

    /* none of these differ-by-one-field responses may match the pending query. */
    cf_dns_correlator_on_response(c, &d_id, 1100, mk_ctx(71));
    cf_dns_correlator_on_response(c, &d_name, 1100, mk_ctx(72));
    cf_dns_correlator_on_response(c, &d_type, 1100, mk_ctx(73));
    cf_dns_correlator_on_response(c, &d_port, 1100, mk_ctx(74));
    CU_ASSERT_EQUAL(h.unmatched, 4);
    CU_ASSERT_EQUAL(h.observed, 0);
    CU_ASSERT_EQUAL(depth(c), 1); /* base still pending */

    /* the exact key matches. */
    cf_dns_correlator_on_response(c, &base, 1100, mk_ctx(75));
    CU_ASSERT_EQUAL(h.observed, 1);
    CU_ASSERT_EQUAL(h.last_query_val, 70);
    CU_ASSERT_EQUAL(depth(c), 0);

    finish(c, &h);
}

static void test_dns_0x20_case_matches(void)
{
    /* DNS-0x20 randomizes case on the wire; the key carries the lowercased,
     * 0x20-normalized qname, so query and response canonicalize identically
     * and still match. Same canonical qname -> same key. */
    harness_t h;
    cf_dns_correlator_t *c = new_corr(&h, 16, CF_DNS_ON_FULL_DROP_NEWEST);
    cf_dns_txn_key_t kq = mkkey(0x8888, "example.org", 1, 40060);
    cf_dns_txn_key_t kr = mkkey(0x8888, "example.org", 1, 40060);

    cf_dns_correlator_on_query(c, &kq, 1000, mk_ctx(80));
    cf_dns_correlator_on_response(c, &kr, 1400, mk_ctx(81));
    CU_ASSERT_EQUAL(h.observed, 1);
    CU_ASSERT_EQUAL(h.last_rtt, 400);
    CU_ASSERT_EQUAL(depth(c), 0);

    finish(c, &h);
}

static void test_new_rejects_bad_config(void)
{
    cf_dns_correlator_config_t cfg;
    harness_t h;

    memset(&h, 0, sizeof(h));
    cfg.capacity = 0;
    cfg.query_timeout_nanos = TIMEOUT_NS;
    cfg.on_table_full = CF_DNS_ON_FULL_DROP_NEWEST;
    CU_ASSERT_PTR_NULL(cf_dns_correlator_new(&cfg, emit_cb, &h));

    cfg.capacity = 8;
    cfg.query_timeout_nanos = 0;
    CU_ASSERT_PTR_NULL(cf_dns_correlator_new(&cfg, emit_cb, &h));

    cfg.query_timeout_nanos = TIMEOUT_NS;
    CU_ASSERT_PTR_NULL(cf_dns_correlator_new(&cfg, NULL, &h));
    CU_ASSERT_PTR_NULL(cf_dns_correlator_new(NULL, emit_cb, &h));

    /* NULL-safe teardown / stats. */
    cf_dns_correlator_free(NULL);
    cf_dns_correlator_stats(NULL, NULL);
}

/* ---- driver -------------------------------------------------------------- */

int main(void)
{
    CU_pSuite suite;
    unsigned int failed;

    if (CU_initialize_registry() != CUE_SUCCESS)
        return (int)CU_get_error();

    suite = CU_add_suite("correlation", NULL, NULL);
    if (!suite) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    if (!CU_add_test(suite, "query then matching response -> OBSERVED", test_match_observed) ||
        !CU_add_test(suite, "response with no pending query -> UNMATCHED", test_response_unmatched) ||
        !CU_add_test(suite, "timeout eviction then late response", test_timeout_then_late_response) ||
        !CU_add_test(suite, "same-key collision evicts older", test_same_key_collision) ||
        !CU_add_test(suite, "table full: drop_newest", test_table_full_drop_newest) ||
        !CU_add_test(suite, "table full: drop_oldest", test_table_full_drop_oldest) ||
        !CU_add_test(suite, "negative and large RTT flagged invalid", test_rtt_invalid) ||
        !CU_add_test(suite, "free() drains pending as UNANSWERED", test_free_drains_pending) ||
        !CU_add_test(suite, "distinct keys do not collide", test_key_isolation) ||
        !CU_add_test(suite, "0x20-normalized qname still matches", test_dns_0x20_case_matches) ||
        !CU_add_test(suite, "new() rejects bad config", test_new_rejects_bad_config)) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();

    failed = CU_get_number_of_tests_failed();

    CU_cleanup_registry();

    return failed > 0 ? 1 : 0;
}
