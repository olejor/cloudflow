/* CUnit acceptance tests for the WP-04 cf_queue hardening. Standalone
 * binary (build/cf_queue_test), separate from cf_core_test, per the
 * tests/unit/Makefile "one binary per WP" pattern -- see that Makefile's
 * header comment. Pattern lifted from a prior syslog-collector
 * prototype's queue unit test (read-only reference, not modified).
 *
 * Single-threaded tests cover the API contract: init/destroy, the
 * full/empty boundary conditions, payload integrity, and wrap-around across
 * many cycles. The final test is a genuine 2-thread producer/consumer
 * stress run that exercises the acquire/release pairing documented in
 * cf_queue.c under real concurrency; it is also compiled (via
 * `make test-tsan` in this directory) directly against an
 * -fsanitize=thread build of cf_queue.c to confirm there is no reported
 * data race.
 *
 * Note on CUnit + threads: CU_ASSERT et al. mutate CUnit's global test
 * registry and are not documented as thread-safe, so the producer/consumer
 * threads below never call them directly. They only record plain counters;
 * the test function (running on CUnit's own thread) asserts on those
 * counters after pthread_join().
 */

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cf_queue.h"

/* ---- init/destroy ------------------------------------------------- */

static void test_init_destroy(void)
{
    cf_queue_t q;
    int rc;

    memset(&q, 0, sizeof(q));

    /* Invalid arguments are rejected without touching *queue. */
    CU_ASSERT_EQUAL(cf_queue_init(NULL, 8, sizeof(uint32_t)), -1);
    CU_ASSERT_EQUAL(cf_queue_init(&q, 1, sizeof(uint32_t)), -1); /* capacity < 2 */
    CU_ASSERT_EQUAL(cf_queue_init(&q, 8, 0), -1);                /* element_size == 0 */

    rc = cf_queue_init(&q, 8, sizeof(uint32_t));
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_PTR_NOT_NULL(q.storage);
    CU_ASSERT_EQUAL(cf_queue_capacity(&q), 7); /* capacity - 1 usable slots */
    CU_ASSERT_EQUAL(cf_queue_length(&q), 0);

    cf_queue_destroy(&q);
    CU_ASSERT_PTR_NULL(q.storage);
    CU_ASSERT_EQUAL(cf_queue_capacity(&q), 0);
    CU_ASSERT_EQUAL(cf_queue_length(&q), 0);

    /* destroy(NULL) and double-destroy must not crash. */
    cf_queue_destroy(NULL);
    cf_queue_destroy(&q);
}

/* ---- push-to-capacity ----------------------------------------------
 *
 * cf_queue_init(..., capacity, ...) allocates `capacity` slots but the ring
 * buffer's full/empty disambiguation (next == tail means full) always
 * leaves one slot unused, so only capacity - 1 elements ever fit --
 * exactly what cf_queue_capacity() reports. Verify that contract
 * empirically rather than assuming it.
 */

static void test_push_to_capacity(void)
{
    cf_queue_t q;
    size_t cap;
    size_t pushed = 0;
    uint32_t v;
    int rc;

    rc = cf_queue_init(&q, 8, sizeof(uint32_t));
    CU_ASSERT_EQUAL(rc, 0);

    cap = cf_queue_capacity(&q);
    CU_ASSERT_EQUAL(cap, 7);

    for (v = 0; v < 100; v++) {
        rc = cf_queue_push(&q, &v);
        if (rc != 0)
            break;
        pushed++;
    }

    /* Queue reports "full" (1), not an error (-1), at capacity. */
    CU_ASSERT_EQUAL(rc, 1);
    CU_ASSERT_EQUAL(pushed, cap);
    CU_ASSERT_EQUAL(cf_queue_length(&q), cap);

    /* Popping one element makes exactly one slot available again. */
    {
        uint32_t out;

        rc = cf_queue_pop(&q, &out);
        CU_ASSERT_EQUAL(rc, 0);
        CU_ASSERT_EQUAL(out, 0u);

        v = 999;
        rc = cf_queue_push(&q, &v);
        CU_ASSERT_EQUAL(rc, 0);

        v = 1000;
        rc = cf_queue_push(&q, &v);
        CU_ASSERT_EQUAL(rc, 1); /* full again */
    }

    cf_queue_destroy(&q);
}

/* ---- pop-empty -------------------------------------------------------- */

static void test_pop_empty(void)
{
    cf_queue_t q;
    uint32_t v = 0;
    int rc;

    rc = cf_queue_init(&q, 4, sizeof(uint32_t));
    CU_ASSERT_EQUAL(rc, 0);

    rc = cf_queue_pop(&q, &v);
    CU_ASSERT_NOT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(rc, 1); /* "empty", not an error */

    cf_queue_destroy(&q);
}

/* ---- payload integrity round-trip ------------------------------------ */

typedef struct {
    uint64_t a;
    double b;
    char c[16];
} payload_t;

static void test_payload_roundtrip(void)
{
    cf_queue_t q;
    payload_t in = { .a = 0xdeadbeefcafebabeULL, .b = 3.14159265358979, .c = "hello world" };
    payload_t out;
    int rc;

    rc = cf_queue_init(&q, 4, sizeof(payload_t));
    CU_ASSERT_EQUAL(rc, 0);

    rc = cf_queue_push(&q, &in);
    CU_ASSERT_EQUAL(rc, 0);

    memset(&out, 0, sizeof(out));
    rc = cf_queue_pop(&q, &out);
    CU_ASSERT_EQUAL(rc, 0);

    CU_ASSERT_EQUAL(out.a, in.a);
    CU_ASSERT_DOUBLE_EQUAL(out.b, in.b, 1e-12);
    CU_ASSERT_EQUAL(memcmp(out.c, in.c, sizeof(out.c)), 0);

    cf_queue_destroy(&q);
}

/* ---- wrap-around over many cycles ------------------------------------ */

static void test_wraparound(void)
{
    cf_queue_t q;
    const uint64_t cycles = 1000;
    uint64_t i;
    int rc;

    /* Tiny queue (3 usable slots) so 1000 push/pop cycles wrap the ring
     * many times over; each cycle pushes then immediately pops one
     * sequence number and checks it comes back unchanged. */
    rc = cf_queue_init(&q, 4, sizeof(uint64_t));
    CU_ASSERT_EQUAL(rc, 0);

    for (i = 0; i < cycles; i++) {
        uint64_t out = (uint64_t)-1;

        rc = cf_queue_push(&q, &i);
        CU_ASSERT_EQUAL(rc, 0);

        rc = cf_queue_pop(&q, &out);
        CU_ASSERT_EQUAL(rc, 0);
        CU_ASSERT_EQUAL(out, i);
    }

    CU_ASSERT_EQUAL(cf_queue_length(&q), 0);

    cf_queue_destroy(&q);
}

/* ---- 2-thread stress test --------------------------------------------
 *
 * One producer, one consumer, exactly as cf_queue is specified to be used
 * (D4: single-producer/single-consumer only). The producer pushes
 * STRESS_N sequenced 64-byte elements, spin-retrying on "full"; the
 * consumer pops them, spin-retrying on "empty", and checks both strict
 * sequence ordering and a per-element checksum over the payload bytes.
 * This is the concurrency test that `make test-tsan` recompiles with
 * -fsanitize=thread to confirm the acquire/release pairing in cf_queue.c
 * is race-free.
 */

#define STRESS_N ((uint64_t)1000000)
#define STRESS_ELEM_SIZE 64
#define STRESS_QUEUE_CAPACITY 1024

typedef struct {
    uint64_t seq;
    uint64_t checksum;
    unsigned char payload[STRESS_ELEM_SIZE - 2 * sizeof(uint64_t)];
} stress_elem_t;

static uint64_t stress_checksum(uint64_t seq, const unsigned char *payload, size_t len)
{
    /* FNV-1a, seeded with seq so the checksum also depends on which
     * element this payload claims to belong to. */
    uint64_t h = 1469598103934665603ULL ^ seq;
    size_t i;

    for (i = 0; i < len; i++) {
        h ^= payload[i];
        h *= 1099511628211ULL;
    }

    return h;
}

static void stress_fill_elem(stress_elem_t *e, uint64_t seq)
{
    size_t i;

    e->seq = seq;
    for (i = 0; i < sizeof(e->payload); i++)
        e->payload[i] = (unsigned char)((seq * 2654435761ULL) + i);
    e->checksum = stress_checksum(seq, e->payload, sizeof(e->payload));
}

typedef struct {
    cf_queue_t *q;
    uint64_t n;
} stress_producer_arg_t;

typedef struct {
    cf_queue_t *q;
    uint64_t n;
    uint64_t consumed;
    uint64_t next_expected_seq;
    uint64_t out_of_order;
    uint64_t checksum_mismatches;
    uint64_t pop_errors;
} stress_consumer_arg_t;

static void *stress_producer_main(void *arg)
{
    stress_producer_arg_t *a = arg;
    uint64_t i;

    for (i = 0; i < a->n; i++) {
        stress_elem_t e;
        int rc;

        stress_fill_elem(&e, i);

        do {
            rc = cf_queue_push(a->q, &e);
        } while (rc == 1); /* full: spin-retry, consumer is draining */
    }

    return NULL;
}

static void *stress_consumer_main(void *arg)
{
    stress_consumer_arg_t *a = arg;
    uint64_t i;

    for (i = 0; i < a->n; i++) {
        stress_elem_t e;
        int rc;
        uint64_t expected_checksum;

        do {
            rc = cf_queue_pop(a->q, &e);
        } while (rc == 1); /* empty: spin-retry, producer is still filling */

        if (rc != 0) {
            a->pop_errors++;
            continue;
        }

        a->consumed++;

        if (e.seq != a->next_expected_seq)
            a->out_of_order++;
        a->next_expected_seq = e.seq + 1;

        expected_checksum = stress_checksum(e.seq, e.payload, sizeof(e.payload));
        if (expected_checksum != e.checksum)
            a->checksum_mismatches++;
    }

    return NULL;
}

static void test_stress_spsc(void)
{
    cf_queue_t q;
    pthread_t producer_thread;
    pthread_t consumer_thread;
    stress_producer_arg_t producer_arg;
    stress_consumer_arg_t consumer_arg;
    int rc;

    CU_ASSERT_EQUAL(sizeof(stress_elem_t), STRESS_ELEM_SIZE);

    rc = cf_queue_init(&q, STRESS_QUEUE_CAPACITY, sizeof(stress_elem_t));
    CU_ASSERT_EQUAL_FATAL(rc, 0);

    producer_arg.q = &q;
    producer_arg.n = STRESS_N;

    memset(&consumer_arg, 0, sizeof(consumer_arg));
    consumer_arg.q = &q;
    consumer_arg.n = STRESS_N;

    CU_ASSERT_EQUAL_FATAL(pthread_create(&producer_thread, NULL, stress_producer_main, &producer_arg), 0);
    CU_ASSERT_EQUAL_FATAL(pthread_create(&consumer_thread, NULL, stress_consumer_main, &consumer_arg), 0);

    CU_ASSERT_EQUAL(pthread_join(producer_thread, NULL), 0);
    CU_ASSERT_EQUAL(pthread_join(consumer_thread, NULL), 0);

    CU_ASSERT_EQUAL(consumer_arg.consumed, STRESS_N);
    CU_ASSERT_EQUAL(consumer_arg.pop_errors, 0);
    CU_ASSERT_EQUAL(consumer_arg.out_of_order, 0);
    CU_ASSERT_EQUAL(consumer_arg.checksum_mismatches, 0);
    CU_ASSERT_EQUAL(consumer_arg.next_expected_seq, STRESS_N);
    CU_ASSERT_EQUAL(cf_queue_length(&q), 0);

    cf_queue_destroy(&q);
}

/* ---- driver ------------------------------------------------------- */

int main(void)
{
    CU_pSuite suite;
    unsigned int failed;

    if (CU_initialize_registry() != CUE_SUCCESS)
        return (int)CU_get_error();

    suite = CU_add_suite("cf_queue", NULL, NULL);
    if (!suite) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    if (!CU_add_test(suite, "init/destroy", test_init_destroy) ||
        !CU_add_test(suite, "push to capacity reports full at capacity() elements", test_push_to_capacity) ||
        !CU_add_test(suite, "pop from empty queue reports empty, not error", test_pop_empty) ||
        !CU_add_test(suite, "payload round-trips intact", test_payload_roundtrip) ||
        !CU_add_test(suite, "wrap-around over 1000 push/pop cycles", test_wraparound) ||
        !CU_add_test(suite, "2-thread SPSC stress test (1e6 elements)", test_stress_spsc)) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();

    failed = CU_get_number_of_tests_failed();

    CU_cleanup_registry();

    return failed > 0 ? 1 : 0;
}
