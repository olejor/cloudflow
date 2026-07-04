#ifndef CF_SINK_CORE_HEC_H
#define CF_SINK_CORE_HEC_H

/* Shared sink spine (A1) -- batched Splunk HEC delivery (libcurl) with
 * retry/backoff/bisect.
 *
 * Retry policy (docs/splunk-output.md, "HEC delivery and retry"):
 * network errors/timeouts/HTTP 429/5xx back off 1s doubling to a 30s cap and
 * retry forever (Redis is the buffer). Other 4xx bisect the batch recursively
 * (floor size 1) to isolate the poison event(s), which are reported back for
 * dead-lettering + XACK while the rest are delivered.
 *
 * The endpoint is parameterized: the client POSTs to hec_url + hec_path (the
 * event sink uses /services/collector/event; the designed metrics sink uses
 * /services/collector). The `line` bytes of each item are opaque to the
 * client -- it concatenates them with '\n' and POSTs the result -- so a
 * transform may put one or several newline-delimited JSON objects in one item.
 *
 * Keep-alive: one reused curl easy handle. TLS verification is on by default;
 * disabling it logs a loud warning. The backoff sleep is injectable so tests
 * never sleep for real. The token is set as an Authorization header and is
 * never logged. */

#include <stddef.h>
#include <stdint.h>

#include "cf_sink_config.h"
#include "cf_sink_stats.h"

typedef struct cf_hec_client cf_hec_client_t;

typedef struct {
    const char *stream;
    const char *entry_id;
    const char *line; /* HEC payload bytes for one entry (no trailing newline) */
    const uint8_t *payload;
    size_t payload_len;
} cf_batch_item_t;

/* Creates a client. Resolves the token from the env (fatal if unset: returns
 * NULL and writes errbuf). POSTs to hec->hec_url concatenated with
 * hec->hec_path. */
cf_hec_client_t *cf_hec_client_new(const cf_hec_config_t *hec, cf_stats_t *stats, char *errbuf,
                                   size_t errcap);
void cf_hec_client_free(cf_hec_client_t *c);

/* Injects the backoff sleep (seconds). Default sleeps for real. */
void cf_hec_client_set_sleep_fn(cf_hec_client_t *c, void (*sleep_fn)(double seconds, void *ctx),
                                void *ctx);

/* Delivers `items`. On return delivered[i]==1 for items that got a 2xx and
 * poison[i]==1 for items to be dead-lettered (reason hec_rejected); for
 * poison items poison_errs[i] is a malloc'd short message the caller frees.
 * Retryable failures are retried internally and never returned. Returns 0. */
int cf_hec_client_send_batch(cf_hec_client_t *c, const cf_batch_item_t *items, size_t n,
                             uint8_t *delivered, uint8_t *poison, char **poison_errs);

/* Expose the client as a pluggable delivery client (cf_sink_delivery.h). The
 * returned value borrows `c`: its send_batch calls cf_hec_client_send_batch
 * and its free calls cf_hec_client_free. The full struct is defined in
 * cf_sink_delivery.h (which includes this header for cf_batch_item_t); it is
 * only forward-declared here to keep the delivery interface layered on top of
 * -- not tangled into -- the HEC client. */
struct cf_sink_delivery cf_hec_client_as_delivery(cf_hec_client_t *c);

#endif
