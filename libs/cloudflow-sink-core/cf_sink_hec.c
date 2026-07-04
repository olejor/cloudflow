#include "cf_sink_hec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

#include "cf_log.h"
#include "cf_sink_delivery.h"
#include "cf_sink_httpdeliver.h"
#include "cf_stats.h"
#include "cf_time.h"

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

/* The HEC post-once primitive (cf_post_once_fn): builds nothing itself -- it
 * POSTs the already-concatenated `body` once and returns the HTTP status, or
 * <=0 for a transport error. The shared retry/bisection helper
 * (cf_sink_httpdeliver) wraps this with the backoff + poison-bisection policy.
 * Splunk-specific: the URL, the "Authorization: Splunk <token>" header and the
 * Content-Type are already set on the reused keep-alive handle. The token is
 * never logged; on a transport error the curl error string is logged (never
 * the token) and copied into errbuf. */
static long hec_post_once(void *ctx, const uint8_t *body, size_t len, char *errbuf, size_t errcap)
{
    cf_hec_client_t *c = ctx;
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
        cf_log(CF_LOG_WARN, "HEC request failed, retrying", "error", curl_easy_strerror(res),
               NULL);
        if (errbuf && errcap)
            snprintf(errbuf, errcap, "%s", curl_easy_strerror(res));
        return -1; /* transport error -> retryable */
    }

    curl_easy_getinfo(c->curl, CURLINFO_RESPONSE_CODE, &status);
    if (errbuf && errcap)
        snprintf(errbuf, errcap, "%s", rb.buf); /* response-body prefix for poison msg */
    return status;
}

int cf_hec_client_send_batch(cf_hec_client_t *c, const cf_batch_item_t *items, size_t n,
                             uint8_t *delivered, uint8_t *poison, char **poison_errs)
{
    return cf_sink_http_deliver_batched(hec_post_once, c, items, n, delivered, poison, poison_errs,
                                        c->sleep_fn, c->sleep_ctx, c->stats);
}

/* ---- delivery interface adapter ---------------------------------------- */

static int hec_delivery_send_batch(void *ctx, const cf_batch_item_t *items, size_t n,
                                   uint8_t *delivered, uint8_t *poison, char **poison_errs)
{
    return cf_hec_client_send_batch((cf_hec_client_t *)ctx, items, n, delivered, poison,
                                    poison_errs);
}

static void hec_delivery_free(void *ctx)
{
    cf_hec_client_free((cf_hec_client_t *)ctx);
}

struct cf_sink_delivery cf_hec_client_as_delivery(cf_hec_client_t *c)
{
    cf_sink_delivery_t d;
    d.ctx = c;
    d.send_batch = hec_delivery_send_batch;
    d.free = hec_delivery_free;
    return d;
}
