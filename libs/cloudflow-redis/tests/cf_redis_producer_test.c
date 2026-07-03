/* CUnit acceptance tests for the WP-09 Redis XADD producer
 * (cf_redis_producer.h/.c). Per the WP-09 task instructions this binary is
 * built and run by libs/cloudflow-redis/Makefile's own `test` target (NOT
 * wired into tests/unit/Makefile, which a parallel WP owns).
 *
 * The suite spawns a private redis-server (fork/exec, `--port 6399 --save
 * ''`, cwd = a fresh temp dir) so it needs no external Redis and cannot
 * collide with a developer's local instance; if the redis-server binary is
 * not on PATH the suite is skipped cleanly (a message on stdout, exit 0)
 * rather than failing the build.
 *
 * Three tests, matching the WP-09 acceptance criteria in
 * docs/design/03-source-dhcp.md:
 *
 *   A. round-trip: push N=500 items across both DHCP streams with distinct,
 *      deterministic payload bytes; stop; verify via a raw hiredis
 *      connection that XLEN sums to N and every XRANGE entry's fields
 *      (schema/version/encoding/event_type) and payload round-trip exactly.
 *   B. reconnect / no silent loss: push 100, sever the connection with
 *      CLIENT KILL, push 100 more, stop; assert
 *      delivered (XLEN sum) + stats.events_lost_total == 200 and
 *      stats.redis_reconnects_total >= 1.
 *   C. stop drains queued items: push 50, stop immediately (no settling
 *      time), assert XLEN == 50 -- cf_redis_producer_stop() itself must
 *      drain and flush before returning.
 *
 * None of the tests call cf_stop_notify(): stopping relies solely on
 * cf_redis_producer_stop()'s producer-local stop flag, which is itself part
 * of what these tests demonstrate (shutdown must work without the
 * process-wide stop flag).
 */

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include <hiredis/hiredis.h>

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "cf_queue.h"
#include "cf_redis_producer.h"
#include "cf_stats.h"
#include "cf_time.h"
#include "cloudflow.h"

/* ---- private redis-server lifecycle ------------------------------------ */

#define TEST_REDIS_PORT 6399

static pid_t g_redis_pid = -1;
static char g_redis_tmpdir[64];

static int redis_server_available(void)
{
    FILE *fp = popen("command -v redis-server 2>/dev/null", "r");
    char buf[512];
    size_t n;

    if (!fp)
        return 0;

    n = fread(buf, 1, sizeof(buf) - 1, fp);
    pclose(fp);

    return n > 0;
}

static int start_redis_server(void)
{
    char portbuf[16];
    pid_t pid;

    snprintf(g_redis_tmpdir, sizeof(g_redis_tmpdir), "/tmp/cf_redis_test_XXXXXX");
    if (!mkdtemp(g_redis_tmpdir)) {
        g_redis_tmpdir[0] = '\0';
        return -1;
    }

    snprintf(portbuf, sizeof(portbuf), "%d", TEST_REDIS_PORT);

    pid = fork();
    if (pid < 0)
        return -1;

    if (pid == 0) {
        int devnull;

        if (chdir(g_redis_tmpdir) != 0)
            _exit(127);

        devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
        }

        execlp("redis-server", "redis-server", "--port", portbuf, "--save", "", (char *)NULL);
        _exit(127);
    }

    g_redis_pid = pid;

    return 0;
}

static int wait_for_redis_ready(void)
{
    int attempt;

    for (attempt = 0; attempt < 100; attempt++) {
        struct timeval tv;
        redisContext *c;

        tv.tv_sec = 0;
        tv.tv_usec = 100000;

        c = redisConnectWithTimeout("127.0.0.1", TEST_REDIS_PORT, tv);
        if (c && !c->err) {
            redisReply *r = redisCommand(c, "PING");
            int ok = r && r->type == REDIS_REPLY_STATUS && r->str && strcmp(r->str, "PONG") == 0;

            if (r)
                freeReplyObject(r);
            redisFree(c);

            if (ok)
                return 0;
        } else if (c) {
            redisFree(c);
        }

        usleep(50000);
    }

    return -1;
}

static void stop_redis_server(void)
{
    if (g_redis_pid > 0) {
        int status;
        int i;
        pid_t r = 0;

        kill(g_redis_pid, SIGTERM);

        for (i = 0; i < 50; i++) {
            r = waitpid(g_redis_pid, &status, WNOHANG);
            if (r == g_redis_pid)
                break;
            usleep(100000);
        }

        if (r != g_redis_pid) {
            kill(g_redis_pid, SIGKILL);
            waitpid(g_redis_pid, &status, 0);
        }

        g_redis_pid = -1;
    }

    if (g_redis_tmpdir[0] != '\0') {
        char cmd[128];

        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_redis_tmpdir);
        if (system(cmd) != 0) {
            /* best-effort cleanup only -- nothing sensible to do if it
             * fails, and failing the test run over a leftover temp dir
             * would be misleading. */
        }
        g_redis_tmpdir[0] = '\0';
    }
}

/* ---- test helpers -------------------------------------------------------- */

#define TEST_PAYLOAD_LEN 256

static void wait_ms(unsigned int ms)
{
    struct timespec ts;

    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

static redisContext *connect_admin(void)
{
    struct timeval tv;

    tv.tv_sec = 2;
    tv.tv_usec = 0;

    return redisConnectWithTimeout("127.0.0.1", TEST_REDIS_PORT, tv);
}

static void flushall(redisContext *c)
{
    redisReply *r = redisCommand(c, "FLUSHALL");

    if (r)
        freeReplyObject(r);
}

static void kill_other_clients(redisContext *admin)
{
    redisReply *r = redisCommand(admin, "CLIENT KILL TYPE normal SKIPME yes");

    if (r)
        freeReplyObject(r);
}

static long long xlen(redisContext *c, const char *stream)
{
    redisReply *r = redisCommand(c, "XLEN %s", stream);
    long long v = 0;

    CU_ASSERT_PTR_NOT_NULL_FATAL(r);
    CU_ASSERT_EQUAL(r->type, REDIS_REPLY_INTEGER);
    if (r->type == REDIS_REPLY_INTEGER)
        v = r->integer;
    freeReplyObject(r);

    return v;
}

static void fill_payload(unsigned char *buf, size_t len, unsigned int seed)
{
    size_t i;

    for (i = 0; i < len; i++)
        buf[i] = (unsigned char)((seed * 2654435761u) + i);
}

static void fill_item(cf_event_item_t *item, cf_stream_id_t stream_id, unsigned int seed)
{
    memset(item, 0, sizeof(*item));
    item->observed_time_unix_nano = cf_now_unix_nano();
    item->stream_id = stream_id;
    item->protocol = (stream_id == CF_STREAM_DHCPV4) ? CF_PROTO_DHCPV4 : CF_PROTO_DHCPV6;
    snprintf(item->event_type, sizeof(item->event_type), "evt-%u", seed);
    item->payload_len = TEST_PAYLOAD_LEN;
    fill_payload(item->payload, TEST_PAYLOAD_LEN, seed);
}

static void push_item(cf_queue_t *q, const cf_event_item_t *item)
{
    int rc;

    do {
        rc = cf_queue_push(q, item);
    } while (rc == 1);

    CU_ASSERT_EQUAL_FATAL(rc, 0);
}

static const redisReply *xrange_field(const redisReply *fields, const char *name)
{
    size_t i;

    for (i = 0; i + 1 < fields->elements; i += 2) {
        if (fields->element[i]->str && strcmp(fields->element[i]->str, name) == 0)
            return fields->element[i + 1];
    }

    return NULL;
}

static void verify_stream_entries(redisContext *c, const char *stream)
{
    redisReply *r = redisCommand(c, "XRANGE %s - +", stream);
    size_t i;

    CU_ASSERT_PTR_NOT_NULL_FATAL(r);
    CU_ASSERT_EQUAL_FATAL(r->type, REDIS_REPLY_ARRAY);

    for (i = 0; i < r->elements; i++) {
        redisReply *entry = r->element[i];
        const redisReply *fields;
        const redisReply *schema;
        const redisReply *version;
        const redisReply *encoding;
        const redisReply *event_type;
        const redisReply *payload;
        unsigned int seed = 0;
        unsigned char expected[TEST_PAYLOAD_LEN];

        CU_ASSERT_EQUAL_FATAL(entry->elements, 2u);
        fields = entry->element[1];

        schema = xrange_field(fields, "schema");
        version = xrange_field(fields, "version");
        encoding = xrange_field(fields, "encoding");
        event_type = xrange_field(fields, "event_type");
        payload = xrange_field(fields, "payload");

        CU_ASSERT_PTR_NOT_NULL_FATAL(schema);
        CU_ASSERT_PTR_NOT_NULL_FATAL(version);
        CU_ASSERT_PTR_NOT_NULL_FATAL(encoding);
        CU_ASSERT_PTR_NOT_NULL_FATAL(event_type);
        CU_ASSERT_PTR_NOT_NULL_FATAL(payload);

        CU_ASSERT_STRING_EQUAL(schema->str, "cloudflow.v1.CloudFlowEvent");
        CU_ASSERT_STRING_EQUAL(version->str, "1");
        CU_ASSERT_STRING_EQUAL(encoding->str, "protobuf");

        CU_ASSERT_EQUAL(sscanf(event_type->str, "evt-%u", &seed), 1);

        fill_payload(expected, sizeof(expected), seed);
        CU_ASSERT_EQUAL(payload->len, sizeof(expected));
        if (payload->len == sizeof(expected))
            CU_ASSERT_EQUAL(memcmp(payload->str, expected, sizeof(expected)), 0);
    }

    freeReplyObject(r);
}

static void make_default_config(cf_redis_producer_config_t *cfg, const char *const *endpoints,
                                 cf_queue_t *q, cf_redis_stats_t *stats)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->endpoints = endpoints;
    cfg->endpoint_count = 1;
    cfg->maxlen_approx = 0;
    cfg->pipeline_max = 64;
    cfg->flush_interval_ms = 20;
    cfg->in = q;
    cfg->stats = stats;
}

/* ---- test A: round-trip -------------------------------------------------- */

#define TEST_A_COUNT 500

static void test_roundtrip(void)
{
    cf_queue_t q;
    cf_redis_stats_t stats;
    cf_redis_producer_config_t cfg;
    char endpoint_buf[32];
    const char *endpoints[1];
    redisContext *admin;
    unsigned int i;
    long long xlen4, xlen6;

    memset(&stats, 0, sizeof(stats));
    snprintf(endpoint_buf, sizeof(endpoint_buf), "127.0.0.1:%d", TEST_REDIS_PORT);
    endpoints[0] = endpoint_buf;

    CU_ASSERT_EQUAL_FATAL(cf_queue_init(&q, 2048, sizeof(cf_event_item_t)), 0);

    admin = connect_admin();
    CU_ASSERT_PTR_NOT_NULL_FATAL(admin);
    flushall(admin);

    make_default_config(&cfg, endpoints, &q, &stats);
    CU_ASSERT_EQUAL_FATAL(cf_redis_producer_start(&cfg), 0);

    for (i = 0; i < TEST_A_COUNT; i++) {
        cf_event_item_t item;

        fill_item(&item, (i % 2 == 0) ? CF_STREAM_DHCPV4 : CF_STREAM_DHCPV6, i);
        push_item(&q, &item);
    }

    cf_redis_producer_stop();

    xlen4 = xlen(admin, cf_stream_name(CF_STREAM_DHCPV4));
    xlen6 = xlen(admin, cf_stream_name(CF_STREAM_DHCPV6));

    CU_ASSERT_EQUAL(xlen4 + xlen6, (long long)TEST_A_COUNT);
    CU_ASSERT_EQUAL(xlen4, (long long)(TEST_A_COUNT / 2));
    CU_ASSERT_EQUAL(xlen6, (long long)(TEST_A_COUNT / 2));

    verify_stream_entries(admin, cf_stream_name(CF_STREAM_DHCPV4));
    verify_stream_entries(admin, cf_stream_name(CF_STREAM_DHCPV6));

    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.events_lost_total), 0ul);
    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.xadd_total), (unsigned long)TEST_A_COUNT);

    redisFree(admin);
    cf_queue_destroy(&q);
}

/* ---- test B: reconnect / no silent loss --------------------------------- */

#define TEST_B_BATCH 100

static void test_reconnect_no_silent_loss(void)
{
    cf_queue_t q;
    cf_redis_stats_t stats;
    cf_redis_producer_config_t cfg;
    char endpoint_buf[32];
    const char *endpoints[1];
    redisContext *admin;
    unsigned int i;
    long long xlen4, xlen6, delivered;
    unsigned long lost, reconnects;

    memset(&stats, 0, sizeof(stats));
    snprintf(endpoint_buf, sizeof(endpoint_buf), "127.0.0.1:%d", TEST_REDIS_PORT);
    endpoints[0] = endpoint_buf;

    CU_ASSERT_EQUAL_FATAL(cf_queue_init(&q, 2048, sizeof(cf_event_item_t)), 0);

    admin = connect_admin();
    CU_ASSERT_PTR_NOT_NULL_FATAL(admin);
    flushall(admin);

    make_default_config(&cfg, endpoints, &q, &stats);
    CU_ASSERT_EQUAL_FATAL(cf_redis_producer_start(&cfg), 0);

    for (i = 0; i < TEST_B_BATCH; i++) {
        cf_event_item_t item;

        fill_item(&item, (i % 2 == 0) ? CF_STREAM_DHCPV4 : CF_STREAM_DHCPV6, i);
        push_item(&q, &item);
    }

    /* Let the first batch fully flush and ack before severing the
     * connection, so the break lands cleanly between the two batches
     * rather than mid-XADD (which would make the outcome depend on exactly
     * which in-flight commands the server had already applied). */
    wait_ms(400);

    kill_other_clients(admin);

    for (i = 0; i < TEST_B_BATCH; i++) {
        cf_event_item_t item;

        fill_item(&item, (i % 2 == 0) ? CF_STREAM_DHCPV4 : CF_STREAM_DHCPV6, TEST_B_BATCH + i);
        push_item(&q, &item);
    }

    cf_redis_producer_stop();

    xlen4 = xlen(admin, cf_stream_name(CF_STREAM_DHCPV4));
    xlen6 = xlen(admin, cf_stream_name(CF_STREAM_DHCPV6));
    delivered = xlen4 + xlen6;

    lost = CF_ATOMIC_READ(stats.events_lost_total);
    reconnects = CF_ATOMIC_READ(stats.redis_reconnects_total);

    CU_ASSERT_EQUAL(delivered + (long long)lost, 2LL * TEST_B_BATCH);
    CU_ASSERT(reconnects >= 1);

    redisFree(admin);
    cf_queue_destroy(&q);
}

/* ---- test C: stop drains queued items ------------------------------------ */

#define TEST_C_COUNT 50

static void test_stop_drains_queue(void)
{
    cf_queue_t q;
    cf_redis_stats_t stats;
    cf_redis_producer_config_t cfg;
    char endpoint_buf[32];
    const char *endpoints[1];
    redisContext *admin;
    unsigned int i;
    long long xlen4, xlen6;

    memset(&stats, 0, sizeof(stats));
    snprintf(endpoint_buf, sizeof(endpoint_buf), "127.0.0.1:%d", TEST_REDIS_PORT);
    endpoints[0] = endpoint_buf;

    CU_ASSERT_EQUAL_FATAL(cf_queue_init(&q, 2048, sizeof(cf_event_item_t)), 0);

    admin = connect_admin();
    CU_ASSERT_PTR_NOT_NULL_FATAL(admin);
    flushall(admin);

    make_default_config(&cfg, endpoints, &q, &stats);
    CU_ASSERT_EQUAL_FATAL(cf_redis_producer_start(&cfg), 0);

    for (i = 0; i < TEST_C_COUNT; i++) {
        cf_event_item_t item;

        fill_item(&item, (i % 2 == 0) ? CF_STREAM_DHCPV4 : CF_STREAM_DHCPV6, i);
        push_item(&q, &item);
    }

    /* No settling time: stop must itself drain+flush before returning. */
    cf_redis_producer_stop();

    xlen4 = xlen(admin, cf_stream_name(CF_STREAM_DHCPV4));
    xlen6 = xlen(admin, cf_stream_name(CF_STREAM_DHCPV6));

    CU_ASSERT_EQUAL(xlen4 + xlen6, (long long)TEST_C_COUNT);
    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.events_lost_total), 0ul);

    redisFree(admin);
    cf_queue_destroy(&q);
}

/* ---- driver --------------------------------------------------------------- */

int main(void)
{
    CU_pSuite suite;
    unsigned int failed;

    if (!redis_server_available()) {
        printf("SKIP: redis-server binary not found on PATH -- skipping cf_redis_producer_test suite\n");
        return 0;
    }

    if (start_redis_server() != 0 || wait_for_redis_ready() != 0) {
        fprintf(stderr, "cf_redis_producer_test: failed to start private redis-server on port %d\n",
                TEST_REDIS_PORT);
        stop_redis_server();
        return 1;
    }

    if (CU_initialize_registry() != CUE_SUCCESS) {
        stop_redis_server();
        return (int)CU_get_error();
    }

    suite = CU_add_suite("cf_redis_producer", NULL, NULL);
    if (!suite ||
        !CU_add_test(suite, "N=500 items across both streams round-trip byte-for-byte", test_roundtrip) ||
        !CU_add_test(suite, "reconnect after CLIENT KILL: delivered + lost == pushed", test_reconnect_no_silent_loss) ||
        !CU_add_test(suite, "stop() drains queued items before returning", test_stop_drains_queue)) {
        CU_cleanup_registry();
        stop_redis_server();
        return (int)CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();

    failed = CU_get_number_of_tests_failed();

    CU_cleanup_registry();
    stop_redis_server();

    return failed > 0 ? 1 : 0;
}
