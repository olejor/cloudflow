#include "ch_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

#include "cf_log.h"
#include "cf_sink_delivery.h"
#include "cf_sink_httpdeliver.h"
#include "cf_time.h"

#define CH_BODY_PREFIX_MAX 200

struct ch_client {
    CURL *curl;
    cf_stats_t *stats;
    struct curl_slist *headers;
    char *url;     /* full POST target incl. ?query=INSERT... -- safe to log */
    char *userpwd; /* "user:password" for HTTP Basic; NULL if no auth. NEVER logged */
    void (*sleep_fn)(double seconds, void *ctx);
    void *sleep_ctx;
};

/* Response-body capture (bounded), used to build the poison message. */
typedef struct {
    char buf[CH_BODY_PREFIX_MAX + 1];
    size_t len;
} resp_body_t;

static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    resp_body_t *rb = userdata;
    size_t total = size * nmemb;
    size_t room = CH_BODY_PREFIX_MAX - rb->len;

    if (room > 0) {
        size_t take = total < room ? total : room;
        memcpy(rb->buf + rb->len, ptr, take);
        rb->len += take;
        rb->buf[rb->len] = '\0';
    }
    return total; /* consume everything so curl is happy */
}

static void default_sleep(double seconds, void *ctx)
{
    (void)ctx;
    if (seconds > 0)
        cf_sleep_ns((int64_t)(seconds * 1e9));
}

/* Build "<url>/?query=<url-encoded INSERT INTO db.table FORMAT JSONEachRow>".
 * A trailing '/' on the base URL is collapsed so we never emit "//?query=".
 * Returns a malloc'd string, or NULL on OOM. */
static char *build_insert_url(CURL *curl, const char *base_url, const char *db, const char *table)
{
    char query[512];
    char *escaped;
    char *full;
    size_t base_len;
    size_t need;

    snprintf(query, sizeof(query), "INSERT INTO %s.%s FORMAT JSONEachRow", db, table);
    escaped = curl_easy_escape(curl, query, 0);
    if (!escaped)
        return NULL;

    base_len = strlen(base_url);
    while (base_len > 0 && base_url[base_len - 1] == '/')
        base_len--; /* drop trailing slashes */

    need = base_len + strlen("/?query=") + strlen(escaped) + 1;
    full = malloc(need);
    if (full)
        snprintf(full, need, "%.*s/?query=%s", (int)base_len, base_url, escaped);
    curl_free(escaped);
    return full;
}

/* Resolve the (optional) HTTP Basic credentials from the env. Returns 0 on
 * success (setting *out_userpwd to a malloc'd "user:pass" or NULL for no auth),
 * -1 on a fatal misconfiguration (writes errbuf, never a secret). */
static int resolve_userpwd(const ch_client_config_t *cfg, char **out_userpwd, char *errbuf,
                           size_t errcap)
{
    const char *user;
    const char *pass;
    size_t need;
    char *up;

    *out_userpwd = NULL;

    if (!cfg->user_env || !cfg->user_env[0])
        return 0; /* no auth configured */

    user = getenv(cfg->user_env);
    if (!user || !*user) {
        if (errbuf && errcap)
            snprintf(errbuf, errcap, "ClickHouse user env var %s is not set or empty",
                     cfg->user_env);
        return -1;
    }
    pass = (cfg->password_env && cfg->password_env[0]) ? getenv(cfg->password_env) : NULL;
    if (!pass)
        pass = ""; /* empty password is allowed */

    need = strlen(user) + 1 + strlen(pass) + 1;
    up = malloc(need);
    if (!up) {
        if (errbuf && errcap)
            snprintf(errbuf, errcap, "out of memory");
        return -1;
    }
    snprintf(up, need, "%s:%s", user, pass);
    *out_userpwd = up;
    return 0;
}

ch_client_t *ch_client_new(const ch_client_config_t *cfg, cf_stats_t *stats, char *errbuf,
                           size_t errcap)
{
    ch_client_t *c;

    c = calloc(1, sizeof(*c));
    if (!c)
        return NULL;
    c->stats = stats;
    c->sleep_fn = default_sleep;

    if (resolve_userpwd(cfg, &c->userpwd, errbuf, errcap) != 0) {
        free(c);
        return NULL;
    }

    c->curl = curl_easy_init();
    if (!c->curl) {
        if (errbuf && errcap)
            snprintf(errbuf, errcap, "curl_easy_init failed");
        free(c->userpwd);
        free(c);
        return NULL;
    }

    c->url = build_insert_url(c->curl, cfg->url, cfg->database, cfg->table);
    if (!c->url) {
        if (errbuf && errcap)
            snprintf(errbuf, errcap, "out of memory building ClickHouse INSERT URL");
        curl_easy_cleanup(c->curl);
        free(c->userpwd);
        free(c);
        return NULL;
    }

    /* The POST body is raw JSONEachRow data; ClickHouse takes the statement
     * from the URL query, so text/plain is the honest content type. */
    c->headers = curl_slist_append(NULL, "Content-Type: text/plain; charset=utf-8");

    curl_easy_setopt(c->curl, CURLOPT_URL, c->url);
    curl_easy_setopt(c->curl, CURLOPT_HTTPHEADER, c->headers);
    curl_easy_setopt(c->curl, CURLOPT_POST, 1L);
    curl_easy_setopt(c->curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(c->curl, CURLOPT_TIMEOUT_MS, (long)cfg->request_timeout_ms);
    curl_easy_setopt(c->curl, CURLOPT_NOSIGNAL, 1L);

    if (c->userpwd) {
        /* HTTP Basic from env creds; the credential string is never logged. */
        curl_easy_setopt(c->curl, CURLOPT_HTTPAUTH, (long)CURLAUTH_BASIC);
        curl_easy_setopt(c->curl, CURLOPT_USERPWD, c->userpwd);
    }

    if (cfg->tls_verify) {
        curl_easy_setopt(c->curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(c->curl, CURLOPT_SSL_VERIFYHOST, 2L);
    } else {
        curl_easy_setopt(c->curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(c->curl, CURLOPT_SSL_VERIFYHOST, 0L);
        cf_log(CF_LOG_WARN,
               "TLS verification disabled for ClickHouse endpoint; this is insecure and "
               "should only be used for local testing",
               "clickhouse_url", c->url, NULL);
    }

    return c;
}

void ch_client_free(ch_client_t *c)
{
    if (!c)
        return;
    if (c->headers)
        curl_slist_free_all(c->headers);
    if (c->curl)
        curl_easy_cleanup(c->curl);
    if (c->userpwd) {
        /* Best-effort scrub of the credential bytes before free. */
        memset(c->userpwd, 0, strlen(c->userpwd));
        free(c->userpwd);
    }
    free(c->url);
    free(c);
}

void ch_client_set_sleep_fn(ch_client_t *c, void (*sleep_fn)(double, void *), void *ctx)
{
    c->sleep_fn = sleep_fn ? sleep_fn : default_sleep;
    c->sleep_ctx = ctx;
}

/* The ClickHouse post-once primitive (cf_post_once_fn): POST the already
 * newline-concatenated JSONEachRow `body` once and return the HTTP status, or
 * <=0 for a transport error. The shared retry/bisection helper wraps this with
 * the backoff + poison-bisection policy: ClickHouse answers 200 on a successful
 * INSERT, 400 for a bad row (bisected out + dead-lettered), and 5xx / network
 * errors are retried. Credentials live on the reused handle and are never
 * logged. */
static long ch_post_once(void *ctx, const uint8_t *body, size_t len, char *errbuf, size_t errcap)
{
    ch_client_t *c = ctx;
    resp_body_t rb;
    CURLcode res;
    long status = 0;

    rb.len = 0;
    rb.buf[0] = '\0';

    curl_easy_setopt(c->curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(c->curl, CURLOPT_POSTFIELDSIZE, (long)len);
    curl_easy_setopt(c->curl, CURLOPT_WRITEDATA, &rb);

    res = curl_easy_perform(c->curl);

    if (res != CURLE_OK) {
        cf_log(CF_LOG_WARN, "ClickHouse request failed, retrying", "error",
               curl_easy_strerror(res), NULL);
        if (errbuf && errcap)
            snprintf(errbuf, errcap, "%s", curl_easy_strerror(res));
        return -1; /* transport error -> retryable */
    }

    curl_easy_getinfo(c->curl, CURLINFO_RESPONSE_CODE, &status);
    if (errbuf && errcap)
        snprintf(errbuf, errcap, "%s", rb.buf); /* response-body prefix for poison msg */
    return status;
}

int ch_client_send_batch(ch_client_t *c, const cf_batch_item_t *items, size_t n,
                         uint8_t *delivered, uint8_t *poison, char **poison_errs)
{
    return cf_sink_http_deliver_batched(ch_post_once, c, items, n, delivered, poison, poison_errs,
                                        c->sleep_fn, c->sleep_ctx, c->stats);
}

/* ---- delivery interface adapter ---------------------------------------- */

static int ch_delivery_send_batch(void *ctx, const cf_batch_item_t *items, size_t n,
                                  uint8_t *delivered, uint8_t *poison, char **poison_errs)
{
    return ch_client_send_batch((ch_client_t *)ctx, items, n, delivered, poison, poison_errs);
}

static void ch_delivery_free(void *ctx)
{
    ch_client_free((ch_client_t *)ctx);
}

struct cf_sink_delivery cf_ch_client_as_delivery(ch_client_t *c)
{
    cf_sink_delivery_t d;
    d.ctx = c;
    d.send_batch = ch_delivery_send_batch;
    d.free = ch_delivery_free;
    return d;
}
