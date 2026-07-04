#include "cf_sink_httpdeliver.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cf_log.h"
#include "cf_stats.h"
#include "cf_time.h"

#define CF_DELIVER_BACKOFF_INITIAL_S 1.0
#define CF_DELIVER_BACKOFF_MAX_S 30.0
#define CF_DELIVER_BODY_PREFIX_MAX 200

static void default_sleep(double seconds, void *ctx)
{
    (void)ctx;
    if (seconds > 0)
        cf_sleep_ns((int64_t)(seconds * 1e9));
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

typedef struct {
    cf_post_once_fn post_once;
    void *post_ctx;
    cf_deliver_sleep_fn sleep_fn;
    void *sleep_ctx;
    cf_stats_t *stats;
} deliver_ctx_t;

/* Recursively delivers items[lo..lo+count). Mirrors the retry/bisection policy
 * that used to live in cf_sink_hec.c's send_range verbatim. */
static void send_range(deliver_ctx_t *d, const cf_batch_item_t *items, size_t lo, size_t count,
                       double backoff, uint8_t *delivered, uint8_t *poison, char **poison_errs)
{
    char body_prefix[CF_DELIVER_BODY_PREFIX_MAX + 1];
    size_t body_len = 0;
    char *body;
    long status = 0;
    size_t mid, i;
    int64_t t0, t1;

    if (count == 0)
        return;

    for (;;) {
        body = build_body(items, lo, count, &body_len);
        if (!body) {
            /* Out of memory building the body: treat as retryable. */
            CF_ATOMIC_INC(d->stats->splunk_retry_total);
            d->sleep_fn(backoff, d->sleep_ctx);
            backoff = backoff * 2 > CF_DELIVER_BACKOFF_MAX_S ? CF_DELIVER_BACKOFF_MAX_S
                                                             : backoff * 2;
            continue;
        }
        body_prefix[0] = '\0';
        t0 = cf_now_mono_nano();
        status = d->post_once(d->post_ctx, (const uint8_t *)body, body_len, body_prefix,
                              sizeof(body_prefix));
        t1 = cf_now_mono_nano();
        free(body);

        if (status >= 200 && status < 300) {
            CF_ATOMIC_STORE(d->stats->splunk_delivery_latency_ms_last,
                            (unsigned long)((t1 - t0) / 1000000LL));
            CF_ATOMIC_ADD(d->stats->splunk_delivery_total, (unsigned long)count);
            CF_ATOMIC_STORE(d->stats->splunk_batch_size_last, (unsigned long)count);
            for (i = 0; i < count; i++)
                delivered[lo + i] = 1;
            return;
        }

        if (status <= 0 || status == 429 || status >= 500) {
            CF_ATOMIC_INC(d->stats->splunk_retry_total);
            CF_ATOMIC_INC(d->stats->splunk_delivery_errors_total);
            d->sleep_fn(backoff, d->sleep_ctx);
            backoff = backoff * 2 > CF_DELIVER_BACKOFF_MAX_S ? CF_DELIVER_BACKOFF_MAX_S
                                                             : backoff * 2;
            continue;
        }

        break; /* non-retryable status -> bisect */
    }

    CF_ATOMIC_INC(d->stats->splunk_delivery_errors_total);

    if (count == 1) {
        char *err = malloc(64 + CF_DELIVER_BODY_PREFIX_MAX);
        if (err)
            snprintf(err, 64 + CF_DELIVER_BODY_PREFIX_MAX, "HTTP %ld: %s", status, body_prefix);
        poison[lo] = 1;
        poison_errs[lo] = err;
        cf_log(CF_LOG_WARN, "delivery rejected single event, dead-lettering", "entry_id",
               items[lo].entry_id, NULL);
        return;
    }

    cf_log(CF_LOG_WARN, "delivery rejected batch with non-retryable status, bisecting", NULL);
    mid = count / 2;
    send_range(d, items, lo, mid, backoff, delivered, poison, poison_errs);
    send_range(d, items, lo + mid, count - mid, backoff, delivered, poison, poison_errs);
}

int cf_sink_http_deliver_batched(cf_post_once_fn post_once, void *post_ctx,
                                 const cf_batch_item_t *items, size_t n, uint8_t *delivered,
                                 uint8_t *poison, char **poison_errs,
                                 cf_deliver_sleep_fn sleep_fn, void *sleep_ctx, cf_stats_t *stats)
{
    deliver_ctx_t d;
    size_t i;

    for (i = 0; i < n; i++) {
        delivered[i] = 0;
        poison[i] = 0;
        poison_errs[i] = NULL;
    }
    if (n == 0)
        return 0;

    d.post_once = post_once;
    d.post_ctx = post_ctx;
    d.sleep_fn = sleep_fn ? sleep_fn : default_sleep;
    d.sleep_ctx = sleep_ctx;
    d.stats = stats;

    send_range(&d, items, 0, n, CF_DELIVER_BACKOFF_INITIAL_S, delivered, poison, poison_errs);
    return 0;
}
