/* CUnit acceptance tests for WP-08 (pcap_replay + cf_queue_push_policy).
 * Standalone binary (sources/cloudflow-source-dhcp/build/rx_reader_test),
 * wired into this directory's own Makefile `test` target -- tests/unit/ is
 * owned by a parallel WP right now, per the WP-08 task instructions (same
 * pattern libs/cloudflow-redis uses for its own tests/).
 *
 * The rx-ring capture path itself needs CAP_NET_RAW and a real interface,
 * so it is not exercised here -- see the manual veth procedure in
 * README.md (and tests/rx_smoke_main.c, the harness that procedure runs).
 * Everything here is pure/offline: pcap_replay_file() and
 * cf_queue_push_policy() directly. */

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cf_queue.h"
#include "cf_stats.h"
#include "cf_time.h"
#include "cloudflow.h"
#include "pcap_replay.h"
#include "queue_policy.h"
#include "rx_reader.h"
#include "source_stats.h"

#define FIXTURE_PATH "../../tests/fixtures/dhcp/v4_discover.pcap"
#define TMP_MULTI_PATH "build/tmp_multi_frame.pcap"
#define TMP_PCAPNG_PATH "build/tmp_pcapng.dat"

/* ---- helpers ----------------------------------------------------------- */

/* Builds a classic-pcap file at `out_path` containing `n_records` copies of
 * `src_path`'s single record (each with ts_sec offset by its index, so the
 * surviving record after a drop policy can be identified). Returns
 * n_records on success, -1 on error. */
static long build_multi_frame_pcap(const char *out_path, const char *src_path, int n_records)
{
    FILE *in;
    FILE *out;
    unsigned char global_hdr[24];
    unsigned char rec_hdr[16];
    unsigned char data[2048];
    uint32_t incl_len;
    uint32_t ts_sec;
    int i;

    in = fopen(src_path, "rb");
    if (!in)
        return -1;

    if (fread(global_hdr, 1, sizeof(global_hdr), in) != sizeof(global_hdr) ||
        fread(rec_hdr, 1, sizeof(rec_hdr), in) != sizeof(rec_hdr)) {
        fclose(in);
        return -1;
    }

    memcpy(&incl_len, rec_hdr + 8, 4);
    if (incl_len > sizeof(data) || fread(data, 1, incl_len, in) != incl_len) {
        fclose(in);
        return -1;
    }
    fclose(in);

    out = fopen(out_path, "wb");
    if (!out)
        return -1;

    fwrite(global_hdr, 1, sizeof(global_hdr), out);

    memcpy(&ts_sec, rec_hdr, 4);
    for (i = 0; i < n_records; i++) {
        uint32_t this_ts = ts_sec + (uint32_t)i;

        memcpy(rec_hdr, &this_ts, 4);
        fwrite(rec_hdr, 1, sizeof(rec_hdr), out);
        fwrite(data, 1, incl_len, out);
    }

    fclose(out);

    return n_records;
}

/* Extracts the ts_sec field the test wrote into the single leftover item's
 * timestamp, so drop-policy tests can tell *which* record survived. */
static uint32_t item_ts_sec(const cf_packet_item_t *item)
{
    return (uint32_t)(item->observed_time_unix_nano / 1000000000LL);
}

/* ---- (a) pcap replay of a single-frame fixture ------------------------- */

static void test_replay_v4_discover_single_packet(void)
{
    cf_queue_t q;
    cf_source_stats_t stats;
    cf_packet_item_t item;
    FILE *fp;
    unsigned char raw[512];
    size_t raw_len;
    uint32_t ts_sec, ts_usec, incl_len, orig_len;
    int64_t expected_ts;
    long n;

    fp = fopen(FIXTURE_PATH, "rb");
    CU_ASSERT_PTR_NOT_NULL_FATAL(fp);
    raw_len = fread(raw, 1, sizeof(raw), fp);
    fclose(fp);
    CU_ASSERT_TRUE_FATAL(raw_len > 40);

    memcpy(&ts_sec, raw + 24, 4);
    memcpy(&ts_usec, raw + 28, 4);
    memcpy(&incl_len, raw + 32, 4);
    memcpy(&orig_len, raw + 36, 4);
    expected_ts = (int64_t)ts_sec * 1000000000LL + (int64_t)ts_usec * 1000LL;

    memset(&stats, 0, sizeof(stats));
    CU_ASSERT_EQUAL_FATAL(cf_queue_init(&q, 8, sizeof(cf_packet_item_t)), 0);

    n = pcap_replay_file(FIXTURE_PATH, &q, &stats, CF_ONFULL_DROP_NEWEST);
    CU_ASSERT_EQUAL(n, 1);
    CU_ASSERT_EQUAL(cf_queue_length(&q), 1u);
    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.packets_received_total), 1UL);
    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.rx_queue_drop_total), 0UL);
    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.packets_truncated_total), 0UL);

    CU_ASSERT_EQUAL_FATAL(cf_queue_pop(&q, &item), 0);
    CU_ASSERT_EQUAL(cf_queue_length(&q), 0u);

    CU_ASSERT_EQUAL(item.observed_time_unix_nano, expected_ts);
    CU_ASSERT_TRUE(item.observed_time_unix_nano > 0);
    CU_ASSERT_EQUAL(item.packet_len, orig_len);
    CU_ASSERT_EQUAL(item.captured_len, incl_len);
    CU_ASSERT_EQUAL(item.flags & CF_PACKET_FLAG_TRUNCATED, 0u);
    CU_ASSERT_EQUAL(memcmp(item.data, raw + 40, incl_len), 0);

    cf_queue_destroy(&q);
}

/* ---- (c) pcapng rejection ------------------------------------------------ */

static void test_replay_rejects_pcapng(void)
{
    FILE *out;
    unsigned char shb[32];
    cf_queue_t q;
    long n;

    memset(shb, 0, sizeof(shb));
    shb[0] = 0x0a;
    shb[1] = 0x0d;
    shb[2] = 0x0d;
    shb[3] = 0x0a; /* pcapng Section Header Block magic, LE on disk */

    out = fopen(TMP_PCAPNG_PATH, "wb");
    CU_ASSERT_PTR_NOT_NULL_FATAL(out);
    fwrite(shb, 1, sizeof(shb), out);
    fclose(out);

    CU_ASSERT_EQUAL_FATAL(cf_queue_init(&q, 4, sizeof(cf_packet_item_t)), 0);

    n = pcap_replay_file(TMP_PCAPNG_PATH, &q, NULL, CF_ONFULL_DROP_NEWEST);
    CU_ASSERT_EQUAL(n, -1);
    CU_ASSERT_EQUAL(cf_queue_length(&q), 0u);

    cf_queue_destroy(&q);
    remove(TMP_PCAPNG_PATH);
}

/* ---- (b) queue-full behavior through pcap_replay_file, per policy ------- */

static void test_replay_queue_full_drop_newest(void)
{
    cf_queue_t q;
    cf_source_stats_t stats;
    cf_packet_item_t item;
    const int n_records = 6;
    long built;
    long n;
    uint32_t base_ts_sec;
    FILE *fp;
    unsigned char raw24[24 + 16];

    fp = fopen(FIXTURE_PATH, "rb");
    CU_ASSERT_PTR_NOT_NULL_FATAL(fp);
    CU_ASSERT_EQUAL_FATAL(fread(raw24, 1, sizeof(raw24), fp), sizeof(raw24));
    fclose(fp);
    memcpy(&base_ts_sec, raw24 + 24, 4);

    built = build_multi_frame_pcap(TMP_MULTI_PATH, FIXTURE_PATH, n_records);
    CU_ASSERT_EQUAL_FATAL(built, n_records);

    memset(&stats, 0, sizeof(stats));
    /* capacity 2 -> exactly 1 usable slot (cf_queue.h: capacity - 1). */
    CU_ASSERT_EQUAL_FATAL(cf_queue_init(&q, 2, sizeof(cf_packet_item_t)), 0);

    n = pcap_replay_file(TMP_MULTI_PATH, &q, &stats, CF_ONFULL_DROP_NEWEST);
    CU_ASSERT_EQUAL(n, n_records);
    CU_ASSERT_EQUAL(cf_queue_length(&q), 1u);
    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.packets_received_total), (unsigned long)n_records);
    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.rx_queue_drop_total), (unsigned long)(n_records - 1));

    /* drop_newest: the first record queued is never displaced. */
    CU_ASSERT_EQUAL_FATAL(cf_queue_pop(&q, &item), 0);
    CU_ASSERT_EQUAL(item_ts_sec(&item), base_ts_sec);

    cf_queue_destroy(&q);
    remove(TMP_MULTI_PATH);
}

static void test_replay_queue_full_drop_oldest(void)
{
    cf_queue_t q;
    cf_source_stats_t stats;
    cf_packet_item_t item;
    const int n_records = 6;
    long built;
    long n;
    uint32_t base_ts_sec;
    FILE *fp;
    unsigned char raw24[24 + 16];

    /* Recover the fixture's base ts_sec so we can check which record
     * survives (the last one pushed, under drop_oldest). */
    fp = fopen(FIXTURE_PATH, "rb");
    CU_ASSERT_PTR_NOT_NULL_FATAL(fp);
    CU_ASSERT_EQUAL_FATAL(fread(raw24, 1, sizeof(raw24), fp), sizeof(raw24));
    fclose(fp);
    memcpy(&base_ts_sec, raw24 + 24, 4);

    built = build_multi_frame_pcap(TMP_MULTI_PATH, FIXTURE_PATH, n_records);
    CU_ASSERT_EQUAL_FATAL(built, n_records);

    memset(&stats, 0, sizeof(stats));
    CU_ASSERT_EQUAL_FATAL(cf_queue_init(&q, 2, sizeof(cf_packet_item_t)), 0);

    n = pcap_replay_file(TMP_MULTI_PATH, &q, &stats, CF_ONFULL_DROP_OLDEST);
    CU_ASSERT_EQUAL(n, n_records);
    CU_ASSERT_EQUAL(cf_queue_length(&q), 1u);
    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.packets_received_total), (unsigned long)n_records);
    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.rx_queue_drop_total), (unsigned long)(n_records - 1));

    /* drop_oldest: only the last record pushed survives. */
    CU_ASSERT_EQUAL_FATAL(cf_queue_pop(&q, &item), 0);
    CU_ASSERT_EQUAL(item_ts_sec(&item), base_ts_sec + (uint32_t)(n_records - 1));

    cf_queue_destroy(&q);
    remove(TMP_MULTI_PATH);
}

static void test_replay_queue_full_block(void)
{
    cf_queue_t q;
    cf_source_stats_t stats;
    cf_packet_item_t item;
    /* Small count: with nobody draining, each drop after the first blocks
     * for the full bounded retry budget (~0.5s) before giving up. */
    const int n_records = 3;
    long built;
    long n;

    built = build_multi_frame_pcap(TMP_MULTI_PATH, FIXTURE_PATH, n_records);
    CU_ASSERT_EQUAL_FATAL(built, n_records);

    memset(&stats, 0, sizeof(stats));
    CU_ASSERT_EQUAL_FATAL(cf_queue_init(&q, 2, sizeof(cf_packet_item_t)), 0);

    n = pcap_replay_file(TMP_MULTI_PATH, &q, &stats, CF_ONFULL_BLOCK);
    CU_ASSERT_EQUAL(n, n_records);
    CU_ASSERT_EQUAL(cf_queue_length(&q), 1u);
    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.packets_received_total), (unsigned long)n_records);
    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.rx_queue_drop_total), (unsigned long)(n_records - 1));

    CU_ASSERT_EQUAL_FATAL(cf_queue_pop(&q, &item), 0);

    cf_queue_destroy(&q);
    remove(TMP_MULTI_PATH);
}

/* ---- (d) cf_queue_push_policy, direct unit tests ------------------------ */

static void test_push_policy_bad_args(void)
{
    cf_queue_t q;
    int v = 1;
    atomic_ulong drops;

    atomic_store(&drops, 0);
    CU_ASSERT_EQUAL_FATAL(cf_queue_init(&q, 4, sizeof(int)), 0);

    CU_ASSERT_EQUAL(cf_queue_push_policy(NULL, &v, sizeof(v), CF_ONFULL_DROP_NEWEST, &drops), -1);
    CU_ASSERT_EQUAL(cf_queue_push_policy(&q, NULL, sizeof(v), CF_ONFULL_DROP_NEWEST, &drops), -1);
    CU_ASSERT_EQUAL(cf_queue_push_policy(&q, &v, sizeof(v) + 1, CF_ONFULL_DROP_NEWEST, &drops), -1);
    CU_ASSERT_EQUAL(atomic_load(&drops), 0UL);

    cf_queue_destroy(&q);
}

static void test_push_policy_drop_newest(void)
{
    cf_queue_t q;
    atomic_ulong drops;
    int a = 1, b = 2;
    int out = 0;

    atomic_store(&drops, 0);
    CU_ASSERT_EQUAL_FATAL(cf_queue_init(&q, 2, sizeof(int)), 0); /* 1 usable slot */

    CU_ASSERT_EQUAL(cf_queue_push_policy(&q, &a, sizeof(a), CF_ONFULL_DROP_NEWEST, &drops), 0);
    CU_ASSERT_EQUAL(cf_queue_push_policy(&q, &b, sizeof(b), CF_ONFULL_DROP_NEWEST, &drops), 1);
    CU_ASSERT_EQUAL(atomic_load(&drops), 1UL);

    CU_ASSERT_EQUAL_FATAL(cf_queue_pop(&q, &out), 0);
    CU_ASSERT_EQUAL(out, a); /* original element was never displaced */

    cf_queue_destroy(&q);
}

static void test_push_policy_drop_oldest(void)
{
    cf_queue_t q;
    atomic_ulong drops;
    int a = 1, b = 2;
    int out = 0;

    atomic_store(&drops, 0);
    CU_ASSERT_EQUAL_FATAL(cf_queue_init(&q, 2, sizeof(int)), 0);

    CU_ASSERT_EQUAL(cf_queue_push_policy(&q, &a, sizeof(a), CF_ONFULL_DROP_OLDEST, &drops), 0);
    CU_ASSERT_EQUAL(cf_queue_push_policy(&q, &b, sizeof(b), CF_ONFULL_DROP_OLDEST, &drops), 0);
    CU_ASSERT_EQUAL(atomic_load(&drops), 1UL);

    CU_ASSERT_EQUAL_FATAL(cf_queue_pop(&q, &out), 0);
    CU_ASSERT_EQUAL(out, b); /* newest element survives */

    cf_queue_destroy(&q);
}

typedef struct {
    cf_queue_t *q;
} drain_arg_t;

static void *drain_one_after_delay(void *arg)
{
    drain_arg_t *a = arg;
    int out;

    cf_sleep_ns(20L * 1000L * 1000L); /* 20ms: let the producer start blocking first */

    while (cf_queue_pop(a->q, &out) != 0)
        cf_sleep_ns(1L * 1000L * 1000L);

    return NULL;
}

static void test_push_policy_block_unblocks_on_drain(void)
{
    cf_queue_t q;
    atomic_ulong drops;
    pthread_t consumer;
    drain_arg_t carg;
    int a = 1, b = 2;

    atomic_store(&drops, 0);
    CU_ASSERT_EQUAL_FATAL(cf_queue_init(&q, 2, sizeof(int)), 0);

    CU_ASSERT_EQUAL(cf_queue_push_policy(&q, &a, sizeof(a), CF_ONFULL_BLOCK, &drops), 0);

    carg.q = &q;
    CU_ASSERT_EQUAL_FATAL(pthread_create(&consumer, NULL, drain_one_after_delay, &carg), 0);

    /* Queue is full; this call must block until the consumer thread above
     * drains the one slot, then succeed without ever counting a drop. */
    CU_ASSERT_EQUAL(cf_queue_push_policy(&q, &b, sizeof(b), CF_ONFULL_BLOCK, &drops), 0);
    CU_ASSERT_EQUAL(atomic_load(&drops), 0UL);

    pthread_join(consumer, NULL);
    cf_queue_destroy(&q);
}

/* ---- driver -------------------------------------------------------------- */

int main(void)
{
    CU_pSuite suite;
    unsigned int failed;

    if (CU_initialize_registry() != CUE_SUCCESS)
        return (int)CU_get_error();

    suite = CU_add_suite("cloudflow-source-dhcp WP-08", NULL, NULL);
    if (!suite) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    if (!CU_add_test(suite, "pcap replay: v4_discover.pcap yields exactly one item",
                      test_replay_v4_discover_single_packet) ||
        !CU_add_test(suite, "pcap replay: pcapng magic is rejected", test_replay_rejects_pcapng) ||
        !CU_add_test(suite, "pcap replay: queue-full drop_newest accounting",
                      test_replay_queue_full_drop_newest) ||
        !CU_add_test(suite, "pcap replay: queue-full drop_oldest accounting",
                      test_replay_queue_full_drop_oldest) ||
        !CU_add_test(suite, "pcap replay: queue-full block accounting (no consumer)",
                      test_replay_queue_full_block) ||
        !CU_add_test(suite, "cf_queue_push_policy: rejects bad arguments", test_push_policy_bad_args) ||
        !CU_add_test(suite, "cf_queue_push_policy: drop_newest", test_push_policy_drop_newest) ||
        !CU_add_test(suite, "cf_queue_push_policy: drop_oldest", test_push_policy_drop_oldest) ||
        !CU_add_test(suite, "cf_queue_push_policy: block unblocks when consumer drains",
                      test_push_policy_block_unblocks_on_drain)) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();

    failed = CU_get_number_of_tests_failed();

    CU_cleanup_registry();

    return failed > 0 ? 1 : 0;
}
