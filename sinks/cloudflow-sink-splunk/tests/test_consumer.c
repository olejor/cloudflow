/* WP-17 consumer suite against a private redis-server (same spawn/skip
 * pattern as libs/cloudflow-redis/tests).
 *
 * docs/splunk-output.md acceptance criteria:
 *  - 100 events -> `--once --stdout` prints 100 mapped events, 0 pending;
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

#include "config.h"
#include "consumer.h"
#include "deadletter.h"
#include "stats.h"

#define STREAM "cloudflow:v1:wire:dhcpv4"
#define GROUP "sink-splunk"

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

static const char *ST_KEYS[] = {"dhcpv4", "dhcpv6"};
static const char *ST_VALS[] = {"cloudflow:dhcpv4", "cloudflow:dhcpv6"};
static const char *STREAMS[] = {STREAM};

static void make_cfg(cf_config_t *c, const char *consumer_name)
{
    memset(c, 0, sizeof(*c));
    c->service.name = (char *)"test";
    c->service.consumer_name = (char *)consumer_name;
    c->redis.streams = (char **)STREAMS;
    c->redis.stream_count = 1;
    c->redis.consumer_group = (char *)GROUP;
    c->redis.read_count = 100;
    c->redis.block_ms = 100;
    c->splunk.index = (char *)"network";
    c->splunk.st_keys = (char **)ST_KEYS;
    c->splunk.st_vals = (char **)ST_VALS;
    c->splunk.st_count = 2;
    c->splunk.batch_size = 500;
    c->splunk.flush_interval_ms = 100000;
}

static uint8_t *g_payload;
static size_t g_payload_len;

/* Returns 0 on success. Uses plain error handling (not CU_ASSERT) because it
 * runs before the CUnit registry/suite is active. */
static int load_fixture(void)
{
    FILE *f = fopen("tests/fixtures/dhcpv4_discover.pb", "rb");
    long n;
    if (!f)
        return -1;
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    g_payload = malloc((size_t)n);
    if (!g_payload || fread(g_payload, 1, (size_t)n, f) != (size_t)n) {
        fclose(f);
        return -1;
    }
    g_payload_len = (size_t)n;
    fclose(f);
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
    cf_config_t cfg;
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
    cf_config_t cfg;
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
    cf_config_t cfg;
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
    cf_consumer_set_stdout(&consumer, out);
    cf_consumer_run_once(&consumer);

    lines = count_lines(out);
    CU_ASSERT_EQUAL(lines, 2); /* 2 good delivered */
    CU_ASSERT_EQUAL(xpending_count(admin), 0);

    decode_errs = atomic_load(&stats.protobuf_decode_errors_total);
    CU_ASSERT_EQUAL(decode_errs, 1ul);

    /* one dead-letter entry, reason=decode_error, original bytes preserved */
    r = redisCommand(admin, "XRANGE %s - +", CF_DEADLETTER_STREAM);
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

    if (load_fixture() != 0) {
        fprintf(stderr, "test_consumer: could not load tests/fixtures/dhcpv4_discover.pb "
                        "(run `make fixtures`)\n");
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
        !CU_add_test(suite, "poison entry dead-lettered (decode_error) and acked", test_poison_dead_lettered)) {
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
