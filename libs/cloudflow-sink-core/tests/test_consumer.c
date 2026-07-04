/* Shared sink spine (A1) consumer suite against a private redis-server (same
 * spawn/skip pattern as libs/cloudflow-redis/tests). Moved out of the event
 * sink: it exercises spine behavior only (consumer group, XAUTOCLAIM reclaim,
 * protobuf-unpack validation, dead-letter), so it drives the consumer with a
 * trivial transform that emits one constant line per event.
 *
 * docs/splunk-output.md acceptance criteria:
 *  - 100 events -> `--once --stdout` prints 100 mapped lines, 0 pending;
 *  - a crashed consumer's pending entries are reclaimed by a second consumer
 *    via XAUTOCLAIM;
 *  - a poison entry is dead-lettered (reason=decode_error) and XACKed.
 *
 * Skips cleanly (exit 0) if redis-server is not on PATH.
 */

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include <hiredis/hiredis.h>

#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "cf_sink_config.h"
#include "cf_sink_consumer.h"
#include "cf_sink_deadletter.h"
#include "cf_sink_stats.h"

#include "cloudflow/v1/envelope.pb-c.h"

#define STREAM "cloudflow:v1:wire:dhcpv4"
#define GROUP "sink-splunk"
#define DEADLETTER "cloudflow:v1:deadletter:sink-splunk"

static pid_t g_redis_pid = -1;
static char g_redis_tmpdir[64];
static int g_port;

static int free_port(void)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    int port = 0;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (s >= 0 && bind(s, (struct sockaddr *)&addr, sizeof(addr)) == 0 &&
        getsockname(s, (struct sockaddr *)&addr, &len) == 0)
        port = ntohs(addr.sin_port);
    if (s >= 0)
        close(s);
    return port;
}

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

static int start_redis(void)
{
    char portbuf[16];
    pid_t pid;

    g_port = free_port();
    if (g_port <= 0)
        return -1;
    snprintf(g_redis_tmpdir, sizeof(g_redis_tmpdir), "/tmp/cf_sink_test_XXXXXX");
    if (!mkdtemp(g_redis_tmpdir)) {
        g_redis_tmpdir[0] = '\0';
        return -1;
    }
    snprintf(portbuf, sizeof(portbuf), "%d", g_port);

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

static redisContext *rconnect(void)
{
    struct timeval tv = {2, 0};
    return redisConnectWithTimeout("127.0.0.1", g_port, tv);
}

static int wait_ready(void)
{
    int attempt;
    for (attempt = 0; attempt < 100; attempt++) {
        redisContext *c = rconnect();
        if (c && !c->err) {
            redisReply *r = redisCommand(c, "PING");
            int ok = r && r->type == REDIS_REPLY_STATUS && strcmp(r->str, "PONG") == 0;
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

static void stop_redis(void)
{
    if (g_redis_pid > 0) {
        int status, i;
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
    if (g_redis_tmpdir[0]) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_redis_tmpdir);
        if (system(cmd) != 0) { /* best-effort */
        }
        g_redis_tmpdir[0] = '\0';
    }
}

/* ---- helpers ------------------------------------------------------------ */

static const char *STREAMS[] = {STREAM};

/* Trivial spine transform: one constant HEC line per event (the event mapping
 * the sink layers on top lives in cloudflow-sink-splunk and is exercised by
 * its golden suite). */
static int test_transform(void *user, const Cloudflow__V1__CloudFlowEvent *ev,
                          const char *source_stream, cf_sink_buf_t *out)
{
    static const char line[] = "{\"event\":\"x\"}";
    (void)user;
    (void)ev;
    (void)source_stream;
    return cf_sink_buf_append(out, line, sizeof(line) - 1);
}

static void make_cfg(cf_sink_config_t *c, const char *consumer_name)
{
    memset(c, 0, sizeof(*c));
    c->service.name = (char *)"test";
    c->service.consumer_name = (char *)consumer_name;
    c->redis.streams = (char **)STREAMS;
    c->redis.stream_count = 1;
    c->redis.consumer_group = (char *)GROUP;
    c->redis.deadletter_stream = (char *)DEADLETTER;
    c->redis.read_count = 100;
    c->redis.block_ms = 100;
    c->hec.index = (char *)"network";
    c->hec.batch_size = 500;
    c->hec.flush_interval_ms = 100000;
}

static uint8_t *g_payload;
static size_t g_payload_len;

/* Build a valid, packed CloudFlowEvent in C (no python bindings needed): the
 * spine only needs it to unpack successfully so the transform is reached. */
static int build_event(void)
{
    Cloudflow__V1__EventEnvelope env = CLOUDFLOW__V1__EVENT_ENVELOPE__INIT;
    Cloudflow__V1__CloudFlowEvent ev = CLOUDFLOW__V1__CLOUD_FLOW_EVENT__INIT;
    size_t n;

    env.event_id = (char *)"ab12cd34ef56ab12cd34ef56ab12cd34";
    env.schema_version = 1;
    env.source_type = (char *)"dhcpv4";
    env.source_host = (char *)"test-host.example.net";
    env.observed_time_unix_nano = 1730000000123456789LL;
    env.stream_name = (char *)STREAM;
    ev.envelope = &env;

    n = cloudflow__v1__cloud_flow_event__get_packed_size(&ev);
    g_payload = malloc(n ? n : 1);
    if (!g_payload)
        return -1;
    cloudflow__v1__cloud_flow_event__pack(&ev, g_payload);
    g_payload_len = n;
    return 0;
}

static void xadd_event(redisContext *c, const uint8_t *payload, size_t len)
{
    redisReply *r = redisCommand(c, "XADD %s * schema %s version %s encoding %s payload %b",
                                 STREAM, "cloudflow.v1.CloudFlowEvent", "1", "protobuf", payload,
                                 len);
    CU_ASSERT_PTR_NOT_NULL_FATAL(r);
    if (r)
        freeReplyObject(r);
}

static void flushall(redisContext *c)
{
    redisReply *r = redisCommand(c, "FLUSHALL");
    if (r)
        freeReplyObject(r);
}

static long long xpending_count(redisContext *c)
{
    redisReply *r = redisCommand(c, "XPENDING %s %s", STREAM, GROUP);
    long long v = -1;
    if (r && r->type == REDIS_REPLY_ARRAY && r->elements >= 1 &&
        r->element[0]->type == REDIS_REPLY_INTEGER)
        v = r->element[0]->integer;
    if (r)
        freeReplyObject(r);
    return v;
}

static int count_lines(FILE *f)
{
    int n = 0, ch, last = '\n';
    rewind(f);
    while ((ch = fgetc(f)) != EOF) {
        if (ch == '\n')
            n++;
        last = ch;
    }
    (void)last;
    return n;
}

/* ---- tests -------------------------------------------------------------- */

static void test_100_events(void)
{
    redisContext *admin = rconnect();
    cf_sink_config_t cfg;
    cf_stats_t stats;
    cf_consumer_t consumer;
    FILE *out;
    int i, lines;

    CU_ASSERT_PTR_NOT_NULL_FATAL(admin);
    flushall(admin);

    for (i = 0; i < 100; i++)
        xadd_event(admin, g_payload, g_payload_len);

    out = fopen("build/consumer_out_100.txt", "w+");
    CU_ASSERT_PTR_NOT_NULL_FATAL(out);

    cf_stats_init(&stats);
    make_cfg(&cfg, "splunk-01");
    CU_ASSERT_EQUAL_FATAL(cf_consumer_init(&consumer, admin, &cfg, &stats), 0);
    cf_consumer_set_transform(&consumer, test_transform, NULL);
    cf_consumer_set_stdout(&consumer, out);
    cf_consumer_run_once(&consumer);

    lines = count_lines(out);
    CU_ASSERT_EQUAL(lines, 100);
    CU_ASSERT_EQUAL(xpending_count(admin), 0);

    cf_consumer_free(&consumer);
    fclose(out);
    redisFree(admin);
}

static void test_xautoclaim_redelivery(void)
{
    redisContext *admin = rconnect();
    cf_sink_config_t cfg;
    cf_stats_t stats;
    cf_consumer_t consumer;
    FILE *out;
    redisReply *r;
    int i, lines;

    CU_ASSERT_PTR_NOT_NULL_FATAL(admin);
    flushall(admin);

    for (i = 0; i < 10; i++)
        xadd_event(admin, g_payload, g_payload_len);

    /* Create the group and let a "crashed" consumer read (mark pending) but
     * never ack. */
    r = redisCommand(admin, "XGROUP CREATE %s %s 0 MKSTREAM", STREAM, GROUP);
    if (r)
        freeReplyObject(r);
    r = redisCommand(admin, "XREADGROUP GROUP %s %s COUNT 10 STREAMS %s >", GROUP,
                     "splunk-crashed", STREAM);
    if (r)
        freeReplyObject(r);
    CU_ASSERT_EQUAL(xpending_count(admin), 10);

    /* Second consumer reclaims via XAUTOCLAIM with min-idle 0 (production
     * uses 60s; tests reclaim immediately). */
    out = fopen("build/consumer_out_reclaim.txt", "w+");
    CU_ASSERT_PTR_NOT_NULL_FATAL(out);
    cf_stats_init(&stats);
    make_cfg(&cfg, "splunk-02");
    CU_ASSERT_EQUAL_FATAL(cf_consumer_init(&consumer, admin, &cfg, &stats), 0);
    cf_consumer_set_transform(&consumer, test_transform, NULL);
    cf_consumer_set_stdout(&consumer, out);
    cf_consumer_set_min_idle_ms(&consumer, 0);
    cf_consumer_run_once(&consumer);

    lines = count_lines(out);
    CU_ASSERT_EQUAL(lines, 10);
    CU_ASSERT_EQUAL(xpending_count(admin), 0);

    cf_consumer_free(&consumer);
    fclose(out);
    redisFree(admin);
}

static void test_poison_dead_lettered(void)
{
    redisContext *admin = rconnect();
    cf_sink_config_t cfg;
    cf_stats_t stats;
    cf_consumer_t consumer;
    FILE *out;
    redisReply *r;
    int lines;
    unsigned long decode_errs;

    CU_ASSERT_PTR_NOT_NULL_FATAL(admin);
    flushall(admin);

    /* two good events + one poison (valid fields, unparseable bytes) */
    xadd_event(admin, g_payload, g_payload_len);
    xadd_event(admin, g_payload, g_payload_len);
    r = redisCommand(admin, "XADD %s * schema %s version %s encoding %s payload %b", STREAM,
                     "cloudflow.v1.CloudFlowEvent", "1", "protobuf",
                     "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", (size_t)11);
    if (r)
        freeReplyObject(r);

    out = fopen("build/consumer_out_poison.txt", "w+");
    CU_ASSERT_PTR_NOT_NULL_FATAL(out);
    cf_stats_init(&stats);
    make_cfg(&cfg, "splunk-01");
    CU_ASSERT_EQUAL_FATAL(cf_consumer_init(&consumer, admin, &cfg, &stats), 0);
    cf_consumer_set_transform(&consumer, test_transform, NULL);
    cf_consumer_set_stdout(&consumer, out);
    cf_consumer_run_once(&consumer);

    lines = count_lines(out);
    CU_ASSERT_EQUAL(lines, 2); /* 2 good delivered */
    CU_ASSERT_EQUAL(xpending_count(admin), 0);

    decode_errs = atomic_load(&stats.protobuf_decode_errors_total);
    CU_ASSERT_EQUAL(decode_errs, 1ul);

    /* one dead-letter entry, reason=decode_error, original bytes preserved */
    r = redisCommand(admin, "XRANGE %s - +", DEADLETTER);
    CU_ASSERT_PTR_NOT_NULL_FATAL(r);
    CU_ASSERT_EQUAL(r->type, REDIS_REPLY_ARRAY);
    CU_ASSERT_EQUAL(r->elements, 1u);
    if (r->type == REDIS_REPLY_ARRAY && r->elements == 1) {
        redisReply *fields = r->element[0]->element[1];
        const char *reason = NULL, *payload = NULL;
        size_t plen = 0, i;
        for (i = 0; i + 1 < fields->elements; i += 2) {
            if (strcmp(fields->element[i]->str, "reason") == 0)
                reason = fields->element[i + 1]->str;
            else if (strcmp(fields->element[i]->str, "payload") == 0) {
                payload = fields->element[i + 1]->str;
                plen = fields->element[i + 1]->len;
            }
        }
        CU_ASSERT_PTR_NOT_NULL(reason);
        if (reason)
            CU_ASSERT_STRING_EQUAL(reason, "decode_error");
        CU_ASSERT_EQUAL(plen, 11u);
        if (payload && plen == 11)
            CU_ASSERT_EQUAL(memcmp(payload, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", 11), 0);
    }
    if (r)
        freeReplyObject(r);

    cf_consumer_free(&consumer);
    fclose(out);
    redisFree(admin);
}

/* Stub delivery client (cf_sink_delivery_t): drives the real flush_hec /
 * dead-letter / ack path without a live HEC endpoint. Reports item 0 as
 * delivered (-> XACK), item 1 as poison (-> dead-letter then XACK) and leaves
 * item 2 as neither (retryable-not-yet-delivered -> stays pending). */
static int stub_send_batch(void *ctx, const cf_batch_item_t *items, size_t n, uint8_t *delivered,
                           uint8_t *poison, char **poison_errs)
{
    size_t i;
    (void)ctx;
    (void)items;
    for (i = 0; i < n; i++) {
        delivered[i] = 0;
        poison[i] = 0;
        poison_errs[i] = NULL;
    }
    if (n > 0)
        delivered[0] = 1;
    if (n > 1) {
        poison[1] = 1;
        poison_errs[1] = strdup("stub poison: HTTP 400");
    }
    /* item 2 (if any) intentionally left neither delivered nor poison */
    return 0;
}

static void test_delivery_mixed_ack(void)
{
    redisContext *admin = rconnect();
    cf_sink_config_t cfg;
    cf_stats_t stats;
    cf_consumer_t consumer;
    cf_sink_delivery_t delivery;
    redisReply *r;

    CU_ASSERT_PTR_NOT_NULL_FATAL(admin);
    flushall(admin);

    /* three valid events -> the transform yields three batch items */
    xadd_event(admin, g_payload, g_payload_len);
    xadd_event(admin, g_payload, g_payload_len);
    xadd_event(admin, g_payload, g_payload_len);

    cf_stats_init(&stats);
    make_cfg(&cfg, "splunk-01");
    CU_ASSERT_EQUAL_FATAL(cf_consumer_init(&consumer, admin, &cfg, &stats), 0);
    cf_consumer_set_transform(&consumer, test_transform, NULL);

    delivery.ctx = NULL;
    delivery.send_batch = stub_send_batch;
    delivery.free = NULL;
    cf_consumer_set_delivery(&consumer, &delivery);

    cf_consumer_run_once(&consumer);

    /* delivered -> acked, poison -> dead-lettered+acked, neither -> pending. */
    CU_ASSERT_EQUAL(xpending_count(admin), 1);

    /* exactly one dead-letter entry, reason=hec_rejected */
    r = redisCommand(admin, "XRANGE %s - +", DEADLETTER);
    CU_ASSERT_PTR_NOT_NULL_FATAL(r);
    CU_ASSERT_EQUAL(r->type, REDIS_REPLY_ARRAY);
    CU_ASSERT_EQUAL(r->elements, 1u);
    if (r->type == REDIS_REPLY_ARRAY && r->elements == 1) {
        redisReply *fields = r->element[0]->element[1];
        const char *reason = NULL;
        size_t i;
        for (i = 0; i + 1 < fields->elements; i += 2) {
            if (strcmp(fields->element[i]->str, "reason") == 0)
                reason = fields->element[i + 1]->str;
        }
        CU_ASSERT_PTR_NOT_NULL(reason);
        if (reason)
            CU_ASSERT_STRING_EQUAL(reason, "hec_rejected");
    }
    if (r)
        freeReplyObject(r);

    cf_consumer_free(&consumer);
    redisFree(admin);
}

int main(void)
{
    CU_pSuite suite;
    unsigned int failed;

    if (!redis_server_available()) {
        printf("SKIP: redis-server not found on PATH -- skipping consumer suite\n");
        return 0;
    }
    if (start_redis() != 0 || wait_ready() != 0) {
        fprintf(stderr, "test_consumer: failed to start private redis-server\n");
        stop_redis();
        return 1;
    }

    if (build_event() != 0) {
        fprintf(stderr, "test_consumer: could not build the test CloudFlowEvent\n");
        stop_redis();
        return 1;
    }

    if (CU_initialize_registry() != CUE_SUCCESS) {
        stop_redis();
        return (int)CU_get_error();
    }
    suite = CU_add_suite("consumer", NULL, NULL);
    if (!suite ||
        !CU_add_test(suite, "100 events processed and acked", test_100_events) ||
        !CU_add_test(suite, "XAUTOCLAIM redelivers a crashed consumer's pending", test_xautoclaim_redelivery) ||
        !CU_add_test(suite, "poison entry dead-lettered (decode_error) and acked", test_poison_dead_lettered) ||
        !CU_add_test(suite, "delivery path: delivered->ack, poison->deadletter+ack, neither->pending", test_delivery_mixed_ack)) {
        CU_cleanup_registry();
        stop_redis();
        return (int)CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    failed = CU_get_number_of_tests_failed();
    CU_cleanup_registry();

    free(g_payload);
    stop_redis();
    return failed > 0 ? 1 : 0;
}
