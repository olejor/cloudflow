#ifndef CF_SINK_CORE_HTTPDELIVER_H
#define CF_SINK_CORE_HTTPDELIVER_H

/* Shared sink spine (A1) -- the reusable batched-HTTP retry/bisection policy,
 * extracted out of the HEC client so any HTTP-style delivery client (the
 * Splunk HEC client today; the designed ClickHouse batched-INSERT client
 * tomorrow) reuses the exact same policy by supplying only its own
 * "POST these bytes once" primitive.
 *
 * Policy (docs/splunk-output.md, "HEC delivery and retry"): the caller's items
 * are concatenated with '\n' and POSTed once via `post_once`. A transport
 * error (post_once returns <=0), HTTP 429 or any 5xx backs off 1s doubling to
 * a 30s cap and retries forever (Redis is the durable buffer). Any other
 * non-2xx status recursively bisects the batch (floor size 1) to isolate the
 * poison item(s), which are reported for dead-lettering + XACK while the rest
 * are delivered. The backoff sleep is injectable so tests never sleep for
 * real. Counters land in the shared cf_stats_t exactly as before. */

#include <stddef.h>
#include <stdint.h>

#include "cf_sink_hec.h" /* cf_batch_item_t */
#include "cf_sink_stats.h"

/* POST `body` (`len` bytes) once. Returns the HTTP status code, or <=0 for a
 * transport error (network/timeout). On a non-2xx HTTP response, writes a
 * short response-body prefix into `errbuf` (used to build the poison message);
 * on a transport error it may write the transport error string there. `errbuf`
 * is always NUL-terminated when errcap > 0. */
typedef long (*cf_post_once_fn)(void *ctx, const uint8_t *body, size_t len, char *errbuf,
                                size_t errcap);

/* Backoff sleep injection (seconds); NULL sleeps for real. */
typedef void (*cf_deliver_sleep_fn)(double seconds, void *ctx);

/* Delivers `items` over `post_once` with the retry/bisection policy above.
 * delivered/poison/poison_errs are (re)initialized here: on return
 * delivered[i]==1 for items that got a 2xx and poison[i]==1 for items to be
 * dead-lettered, with poison_errs[i] a malloc'd short message the caller frees.
 * Returns 0. */
int cf_sink_http_deliver_batched(cf_post_once_fn post_once, void *post_ctx,
                                 const cf_batch_item_t *items, size_t n, uint8_t *delivered,
                                 uint8_t *poison, char **poison_errs,
                                 cf_deliver_sleep_fn sleep_fn, void *sleep_ctx, cf_stats_t *stats);

#endif
