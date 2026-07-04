#include "cf_sink_hec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

#include "cf_log.h"
#include "cf_stats.h"
#include "cf_time.h"

#define CF_HEC_BACKOFF_INITIAL_S 1.0
#define CF_HEC_BACKOFF_MAX_S 30.0
#define CF_HEC_BODY_PREFIX_MAX 200

struct cf_hec_client {
    const cf_hec_config_t *cfg;
    cf_stats_t *stats;
    CURL *curl;
    struct curl_slist *headers;
    char *auth_header; /* "Authorization: Splunk <token>" -- never logged */
    char *url;         /* hec_url + hec_path -- the POST target */
    void (*sleep_fn)(double seconds, void *ctx);
    void *sleep_ctx;
};

/* Response-body capture (bounded). */
typedef struct {
    char buf[CF_HEC_BODY_PREFIX_MAX + 1];
    size_t len;
} resp_body_t;

static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    resp_body_t *rb = userdata;
    size_t total = size * nmemb;
    size_t room = CF_HEC_BODY_PREFIX_MAX - rb->len;

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

cf_hec_client_t *cf_hec_client_new(const cf_hec_config_t *hec, cf_stats_t *stats, char *errbuf,
                                   size_t errcap)
{
    cf_hec_client_t *c;
    const char *token;
    const char *path;
    size_t auth_len, url_len;

    token = cf_sink_resolve_token(hec);
    if (!token) {
        if (errbuf && errcap)
            snprintf(errbuf, errcap, "HEC token env var %s is not set or empty",
                     hec->hec_token_env ? hec->hec_token_env : "(unset)");
        return NULL;
    }

    c = calloc(1, sizeof(*c));
    if (!c)
        return NULL;
    c->cfg = hec;
    c->stats = stats;
    c->sleep_fn = default_sleep;

    /* POST target = hec_url + hec_path. hec_path defaults to "" so a hec_url
     * that already carries the endpoint path is used verbatim. */
    path = hec->hec_path ? hec->hec_path : "";
    url_len = strlen(hec->hec_url) + strlen(path) + 1;
    c->url = malloc(url_len);
    if (!c->url) {
        free(c);
        return NULL;
    }
    snprintf(c->url, url_len, "%s%s", hec->hec_url, path);

    c->curl = curl_easy_init();
    if (!c->curl) {
        if (errbuf && errcap)
            snprintf(errbuf, errcap, "curl_easy_init failed");
        free(c->url);
        free(c);
        return NULL;
    }

    auth_len = strlen("Authorization: Splunk ") + strlen(token) + 1;
    c->auth_header = malloc(auth_len);
    if (!c->auth_header) {
        curl_easy_cleanup(c->curl);
        free(c->url);
        free(c);
        return NULL;
    }
    snprintf(c->auth_header, auth_len, "Authorization: Splunk %s", token);

    c->headers = curl_slist_append(NULL, c->auth_header);
    c->headers = curl_slist_append(c->headers, "Content-Type: application/json");

    curl_easy_setopt(c->curl, CURLOPT_URL, c->url);
    curl_easy_setopt(c->curl, CURLOPT_HTTPHEADER, c->headers);
    curl_easy_setopt(c->curl, CURLOPT_POST, 1L);
    curl_easy_setopt(c->curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(c->curl, CURLOPT_TIMEOUT_MS, (long)hec->request_timeout_ms);
    curl_easy_setopt(c->curl, CURLOPT_NOSIGNAL, 1L);

    if (hec->tls_verify) {
        curl_easy_setopt(c->curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(c->curl, CURLOPT_SSL_VERIFYHOST, 2L);
    } else {
        curl_easy_setopt(c->curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(c->curl, CURLOPT_SSL_VERIFYHOST, 0L);
        cf_log(CF_LOG_WARN,
               "TLS verification disabled for Splunk HEC endpoint; this is insecure and "
               "should only be used for local testing",
               "hec_url", c->url, NULL);
    }

    return c;
}

void cf_hec_client_free(cf_hec_client_t *c)
{
    if (!c)
        return;
    if (c->headers)
        curl_slist_free_all(c->headers);
    if (c->curl)
        curl_easy_cleanup(c->curl);
    free(c->auth_header);
    free(c->url);
    free(c);
}

void cf_hec_client_set_sleep_fn(cf_hec_client_t *c, void (*sleep_fn)(double, void *), void *ctx)
{
    c->sleep_fn = sleep_fn ? sleep_fn : default_sleep;
    c->sleep_ctx = ctx;
}

/* Concatenate items[lo..lo+count) lines with '\n' into a malloc'd buffer. */
static char *build_body(const cf_batch_item_t *items, size_t lo, size_t count, size_t *out_len)
{
    size_t total = 0, i, o = 0;
    char *body;

    for (i = 0; i < count; i++)
        total += strlen(items[lo + i].line) + 1;
    if (total == 0)
        total = 1;
    body = malloc(total);
    if (!body)
        return NULL;
    for (i = 0; i < count; i++) {
        size_t len = strlen(items[lo + i].line);
        if (i > 0)
            body[o++] = '\n';
        memcpy(body + o, items[lo + i].line, len);
        o += len;
    }
    *out_len = o;
    return body;
}

/* One POST attempt. Returns: 0 on 2xx; 1 on retryable (net/429/5xx); 2 on
 * non-retryable 4xx (writes body prefix + status). */
static int post_once(cf_hec_client_t *c, const char *body, size_t body_len, long *status_out,
                     char *body_prefix, size_t prefix_cap)
{
    resp_body_t rb;
    CURLcode res;
    long status = 0;
    int64_t t0, t1;

    rb.len = 0;
    rb.buf[0] = '\0';

    curl_easy_setopt(c->curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(c->curl, CURLOPT_POSTFIELDSIZE, (long)body_len);
    curl_easy_setopt(c->curl, CURLOPT_WRITEDATA, &rb);

    t0 = cf_now_mono_nano();
    res = curl_easy_perform(c->curl);
    t1 = cf_now_mono_nano();

    if (res != CURLE_OK) {
        cf_log(CF_LOG_WARN, "HEC request failed, retrying", "error", curl_easy_strerror(res),
               NULL);
        return 1;
    }

    curl_easy_getinfo(c->curl, CURLINFO_RESPONSE_CODE, &status);
    *status_out = status;

    if (status >= 200 && status < 300) {
        CF_ATOMIC_STORE(c->stats->splunk_delivery_latency_ms_last,
                        (unsigned long)((t1 - t0) / 1000000LL));
        return 0;
    }
    if (status == 429 || status >= 500)
        return 1;

    if (body_prefix && prefix_cap)
        snprintf(body_prefix, prefix_cap, "%s", rb.buf);
    return 2;
}

/* Recursively delivers items[lo..lo+count). */
static void send_range(cf_hec_client_t *c, const cf_batch_item_t *items, size_t lo, size_t count,
                       double backoff, uint8_t *delivered, uint8_t *poison, char **poison_errs)
{
    char body_prefix[CF_HEC_BODY_PREFIX_MAX + 1];
    size_t body_len = 0;
    char *body;
    long status = 0;
    size_t mid, i;
    int rc;

    if (count == 0)
        return;

    for (;;) {
        body = build_body(items, lo, count, &body_len);
        if (!body) {
            /* Out of memory building the body: treat as retryable. */
            CF_ATOMIC_INC(c->stats->splunk_retry_total);
            c->sleep_fn(backoff, c->sleep_ctx);
            backoff = backoff * 2 > CF_HEC_BACKOFF_MAX_S ? CF_HEC_BACKOFF_MAX_S : backoff * 2;
            continue;
        }
        body_prefix[0] = '\0';
        rc = post_once(c, body, body_len, &status, body_prefix, sizeof(body_prefix));
        free(body);

        if (rc == 0) {
            CF_ATOMIC_ADD(c->stats->splunk_delivery_total, (unsigned long)count);
            CF_ATOMIC_STORE(c->stats->splunk_batch_size_last, (unsigned long)count);
            for (i = 0; i < count; i++)
                delivered[lo + i] = 1;
            return;
        }

        if (rc == 1) {
            CF_ATOMIC_INC(c->stats->splunk_retry_total);
            CF_ATOMIC_INC(c->stats->splunk_delivery_errors_total);
            c->sleep_fn(backoff, c->sleep_ctx);
            backoff = backoff * 2 > CF_HEC_BACKOFF_MAX_S ? CF_HEC_BACKOFF_MAX_S : backoff * 2;
            continue;
        }

        break; /* rc == 2: non-retryable 4xx -> bisect */
    }

    CF_ATOMIC_INC(c->stats->splunk_delivery_errors_total);

    if (count == 1) {
        char *err = malloc(64 + CF_HEC_BODY_PREFIX_MAX);
        if (err)
            snprintf(err, 64 + CF_HEC_BODY_PREFIX_MAX, "HTTP %ld: %s", status, body_prefix);
        poison[lo] = 1;
        poison_errs[lo] = err;
        cf_log(CF_LOG_WARN, "HEC rejected single event, dead-lettering", "entry_id",
               items[lo].entry_id, NULL);
        return;
    }

    cf_log(CF_LOG_WARN, "HEC rejected batch with non-retryable status, bisecting", NULL);
    mid = count / 2;
    send_range(c, items, lo, mid, backoff, delivered, poison, poison_errs);
    send_range(c, items, lo + mid, count - mid, backoff, delivered, poison, poison_errs);
}

int cf_hec_client_send_batch(cf_hec_client_t *c, const cf_batch_item_t *items, size_t n,
                             uint8_t *delivered, uint8_t *poison, char **poison_errs)
{
    size_t i;

    for (i = 0; i < n; i++) {
        delivered[i] = 0;
        poison[i] = 0;
        poison_errs[i] = NULL;
    }
    if (n == 0)
        return 0;

    send_range(c, items, 0, n, CF_HEC_BACKOFF_INITIAL_S, delivered, poison, poison_errs);
    return 0;
}
