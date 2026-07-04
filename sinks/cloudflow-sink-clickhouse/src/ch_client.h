#ifndef CF_SINK_CLICKHOUSE_CLIENT_H
#define CF_SINK_CLICKHOUSE_CLIENT_H

/* WP-CH02 -- the ClickHouse delivery client.
 *
 * A keep-alive libcurl handle that POSTs newline-delimited JSONEachRow rows to
 * the ClickHouse HTTP interface:
 *
 *   POST <url>/?query=INSERT+INTO+<db>.<table>+FORMAT+JSONEachRow
 *
 * (the query is URL-encoded). The POST body is exactly the rows the shared
 * batched-HTTP helper concatenates with '\n', which is the JSONEachRow wire
 * form. Modelled on the Splunk HEC client (cf_sink_hec.c): it supplies only a
 * "POST these bytes once -> HTTP status" primitive (ch_post_once) and drives it
 * through cf_sink_http_deliver_batched (cf_sink_httpdeliver.h) so the
 * retry/backoff/bisection policy is REUSED verbatim -- a bad row (ClickHouse
 * 400) bisects to isolate + dead-letter it; server down / 5xx / network errors
 * back off and retry forever (Redis is the durable buffer).
 *
 * Auth (decision D6): HTTP Basic user/password read ONLY from the environment
 * variables named in the config (never a literal secret in YAML, never logged).
 * TLS verification is on by default; disabling it logs a loud warning. The
 * client is exposed as a pluggable cf_sink_delivery_t via
 * cf_ch_client_as_delivery(). */

#include <stddef.h>
#include <stdint.h>

#include "cf_sink_delivery.h" /* cf_sink_delivery_t, cf_batch_item_t (via cf_sink_hec.h) */
#include "cf_sink_stats.h"    /* cf_stats_t */

typedef struct ch_client ch_client_t;

typedef struct {
    const char *url;          /* ClickHouse HTTP base URL, e.g. https://ch:8443 */
    const char *database;     /* target database */
    const char *table;        /* target table */
    const char *user_env;     /* env var NAME holding the HTTP Basic user; "" => no auth */
    const char *password_env; /* env var NAME holding the password; "" => empty password */
    int request_timeout_ms;
    int tls_verify; /* default 1 */
} ch_client_config_t;

/* Creates a client. Resolves the (optional) HTTP Basic credentials from the
 * env vars named by cfg->user_env / cfg->password_env: when user_env is set but
 * its env var is unset/empty this is a fatal error (returns NULL + writes
 * errbuf, never a secret). Returns NULL on any init failure. */
ch_client_t *ch_client_new(const ch_client_config_t *cfg, cf_stats_t *stats, char *errbuf,
                           size_t errcap);
void ch_client_free(ch_client_t *c);

/* Injects the backoff sleep (seconds). Default sleeps for real. */
void ch_client_set_sleep_fn(ch_client_t *c, void (*sleep_fn)(double seconds, void *ctx),
                            void *ctx);

/* Delivers `items` (each item's `line` is one JSONEachRow object). On return
 * delivered[i]==1 for items in a batch that got a 2xx and poison[i]==1 for
 * items to be dead-lettered, with poison_errs[i] a malloc'd short message the
 * caller frees. Retryable failures are retried internally. Returns 0. */
int ch_client_send_batch(ch_client_t *c, const cf_batch_item_t *items, size_t n,
                         uint8_t *delivered, uint8_t *poison, char **poison_errs);

/* Expose the client as a pluggable delivery client (cf_sink_delivery.h). The
 * returned value borrows `c`: its send_batch calls ch_client_send_batch and its
 * free calls ch_client_free. */
struct cf_sink_delivery cf_ch_client_as_delivery(ch_client_t *c);

#endif
