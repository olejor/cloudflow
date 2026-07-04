/* WP-17 HEC client suite against a python http stub (tests/hec_stub.py).
 *
 * docs/splunk-output.md acceptance criteria:
 *  - 5xx then 2xx -> retried, delivered once;
 *  - 400 on a 3-event batch with one poison -> 2 delivered, 1 dead-lettered
 *    (reason=hec_rejected), all reported for XACK;
 *  - the token is sent on the wire but never appears in logs.
 *
 * Backoff is injected (no-op sleep) so the suite never sleeps for real.
 */

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

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
#include "hec.h"
#include "stats.h"

#define TOKEN "SUPER-SECRET-HEC-TOKEN-DO-NOT-LOG"
#define TOKEN_ENV "CF_TEST_HEC_TOKEN"

static int free_port(void)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    int port = 0;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (s >= 0 && bind(s, (struct sockaddr *)&addr, sizeof(addr)) == 0 &&
        getsockname(s, (struct sockaddr *)&addr, &len) == 0)
        port = ntohs(addr.sin_port);
    if (s >= 0)
        close(s);
    return port;
}

static int port_open(int port)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    int ok;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ok = (s >= 0 && connect(s, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    if (s >= 0)
        close(s);
    return ok;
}

static pid_t start_stub(int port, const char *mode, const char *reqlog)
{
    pid_t pid = fork();
    char portbuf[16];
    int i;

    if (pid < 0)
        return -1;
    if (pid == 0) {
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
        }
        snprintf(portbuf, sizeof(portbuf), "%d", port);
        execlp("python3", "python3", "tests/hec_stub.py", portbuf, mode, reqlog, (char *)NULL);
        _exit(127);
    }
    for (i = 0; i < 100; i++) {
        if (port_open(port))
            return pid;
        usleep(50000);
    }
    return pid; /* return anyway; test will fail loudly if unusable */
}

static void stop_stub(pid_t pid)
{
    int status;
    if (pid > 0) {
        kill(pid, SIGTERM);
        waitpid(pid, &status, 0);
    }
}

static int python_available(void)
{
    return system("command -v python3 >/dev/null 2>&1") == 0;
}

static void no_sleep(double s, void *ctx)
{
    (void)s;
    (void)ctx;
}

static void make_cfg(cf_splunk_config_t *s, const char *url)
{
    memset(s, 0, sizeof(*s));
    s->hec_url = (char *)url;
    s->hec_token_env = (char *)TOKEN_ENV;
    s->index = (char *)"";
    s->request_timeout_ms = 2000;
    s->tls_verify = 1;
}

static char *slurp(const char *path)
{
    FILE *f = fopen(path, "rb");
    long n;
    char *buf;
    if (!f)
        return NULL;
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = malloc((size_t)n + 1);
    if (buf && n > 0 && fread(buf, 1, (size_t)n, f) != (size_t)n) {
        free(buf);
        buf = NULL;
    }
    if (buf)
        buf[n > 0 ? n : 0] = '\0';
    fclose(f);
    return buf;
}

/* ---- tests -------------------------------------------------------------- */

static void test_5xx_then_2xx(void)
{
    int port = free_port();
    char url[128], reqlog[64];
    pid_t stub;
    cf_splunk_config_t cfg;
    cf_stats_t stats;
    cf_hec_client_t *client;
    cf_batch_item_t items[2];
    uint8_t delivered[2], poison[2];
    char *poison_errs[2];
    char errbuf[256];
    char *reqs;

    snprintf(reqlog, sizeof(reqlog), "build/hec_reqs_5xx.txt");
    remove(reqlog);
    stub = start_stub(port, "5xx_then_2xx", reqlog);
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/services/collector/event", port);

    setenv(TOKEN_ENV, TOKEN, 1);
    cf_stats_init(&stats);
    make_cfg(&cfg, url);
    client = cf_hec_client_new(&cfg, &stats, errbuf, sizeof(errbuf));
    CU_ASSERT_PTR_NOT_NULL_FATAL(client);
    cf_hec_client_set_sleep_fn(client, no_sleep, NULL);

    memset(items, 0, sizeof(items));
    items[0].stream = "s";
    items[0].entry_id = "1-0";
    items[0].line = "{\"event\":\"e0\"}";
    items[1].stream = "s";
    items[1].entry_id = "2-0";
    items[1].line = "{\"event\":\"e1\"}";

    cf_hec_client_send_batch(client, items, 2, delivered, poison, poison_errs);

    CU_ASSERT_EQUAL(delivered[0], 1);
    CU_ASSERT_EQUAL(delivered[1], 1);
    CU_ASSERT_EQUAL(poison[0], 0);
    CU_ASSERT_EQUAL(poison[1], 0);
    CU_ASSERT_EQUAL(atomic_load(&stats.splunk_delivery_total), 2ul);
    CU_ASSERT_TRUE(atomic_load(&stats.splunk_retry_total) >= 1ul);

    /* The token was sent on the wire (Authorization header). */
    reqs = slurp(reqlog);
    CU_ASSERT_PTR_NOT_NULL(reqs);
    if (reqs) {
        CU_ASSERT_PTR_NOT_NULL(strstr(reqs, "Splunk " TOKEN));
        free(reqs);
    }

    cf_hec_client_free(client);
    stop_stub(stub);
}

static void test_bisect_poison(void)
{
    int port = free_port();
    char url[128], reqlog[64];
    pid_t stub;
    cf_splunk_config_t cfg;
    cf_stats_t stats;
    cf_hec_client_t *client;
    cf_batch_item_t items[3];
    uint8_t delivered[3], poison[3];
    char *poison_errs[3];
    char errbuf[256];

    snprintf(reqlog, sizeof(reqlog), "build/hec_reqs_bisect.txt");
    remove(reqlog);
    stub = start_stub(port, "bisect_poison", reqlog);
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/services/collector/event", port);

    setenv(TOKEN_ENV, TOKEN, 1);
    cf_stats_init(&stats);
    make_cfg(&cfg, url);
    client = cf_hec_client_new(&cfg, &stats, errbuf, sizeof(errbuf));
    CU_ASSERT_PTR_NOT_NULL_FATAL(client);
    cf_hec_client_set_sleep_fn(client, no_sleep, NULL);

    memset(items, 0, sizeof(items));
    items[0].stream = "s";
    items[0].entry_id = "1-0";
    items[0].line = "{\"event\":\"ok1\"}";
    items[1].stream = "s";
    items[1].entry_id = "2-0";
    items[1].line = "{\"event\":\"poison\"}";
    items[2].stream = "s";
    items[2].entry_id = "3-0";
    items[2].line = "{\"event\":\"ok3\"}";

    cf_hec_client_send_batch(client, items, 3, delivered, poison, poison_errs);

    CU_ASSERT_EQUAL(delivered[0], 1);
    CU_ASSERT_EQUAL(delivered[2], 1);
    CU_ASSERT_EQUAL(poison[1], 1);
    CU_ASSERT_EQUAL(delivered[1], 0);
    CU_ASSERT_PTR_NOT_NULL(poison_errs[1]);
    if (poison_errs[1]) {
        CU_ASSERT_PTR_NOT_NULL(strstr(poison_errs[1], "400"));
        free(poison_errs[1]);
    }
    free(poison_errs[0]);
    free(poison_errs[2]);

    cf_hec_client_free(client);
    stop_stub(stub);
}

static void test_token_never_logged(void)
{
    int port = free_port();
    char url[128], reqlog[64];
    pid_t stub;
    cf_splunk_config_t cfg;
    cf_stats_t stats;
    cf_hec_client_t *client;
    cf_batch_item_t item;
    uint8_t delivered[1], poison[1];
    char *poison_errs[1];
    char errbuf[256];
    int saved_stderr, logfd;
    char *logtext;

    snprintf(reqlog, sizeof(reqlog), "build/hec_reqs_log.txt");
    remove(reqlog);
    stub = start_stub(port, "5xx_then_2xx", reqlog);
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/services/collector/event", port);

    setenv(TOKEN_ENV, TOKEN, 1);
    cf_stats_init(&stats);
    make_cfg(&cfg, url);
    client = cf_hec_client_new(&cfg, &stats, errbuf, sizeof(errbuf));
    CU_ASSERT_PTR_NOT_NULL_FATAL(client);
    cf_hec_client_set_sleep_fn(client, no_sleep, NULL);

    /* Capture everything the client writes to stderr during delivery. */
    fflush(stderr);
    saved_stderr = dup(STDERR_FILENO);
    logfd = open("build/hec_stderr.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    dup2(logfd, STDERR_FILENO);

    memset(&item, 0, sizeof(item));
    item.stream = "s";
    item.entry_id = "1-0";
    item.line = "{\"event\":\"e0\"}";
    cf_hec_client_send_batch(client, &item, 1, delivered, poison, poison_errs);

    fflush(stderr);
    dup2(saved_stderr, STDERR_FILENO);
    close(saved_stderr);
    close(logfd);

    CU_ASSERT_EQUAL(delivered[0], 1);

    logtext = slurp("build/hec_stderr.txt");
    CU_ASSERT_PTR_NOT_NULL(logtext);
    if (logtext) {
        /* A retry warning should have been logged (503 first) but never the token. */
        CU_ASSERT_PTR_NULL(strstr(logtext, TOKEN));
        free(logtext);
    }

    free(poison_errs[0]);
    cf_hec_client_free(client);
    stop_stub(stub);
}

int main(void)
{
    CU_pSuite suite;
    unsigned int failed;

    if (!python_available()) {
        printf("SKIP: python3 not found -- skipping HEC stub suite\n");
        return 0;
    }

    if (CU_initialize_registry() != CUE_SUCCESS)
        return (int)CU_get_error();
    suite = CU_add_suite("hec", NULL, NULL);
    if (!suite ||
        !CU_add_test(suite, "5xx then 2xx retried and delivered once", test_5xx_then_2xx) ||
        !CU_add_test(suite, "400 batch bisected: poison isolated, rest delivered", test_bisect_poison) ||
        !CU_add_test(suite, "token sent on wire but never logged", test_token_never_logged)) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    failed = CU_get_number_of_tests_failed();
    CU_cleanup_registry();
    return failed > 0 ? 1 : 0;
}
