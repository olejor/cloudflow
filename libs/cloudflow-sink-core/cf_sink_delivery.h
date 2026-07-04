#ifndef CF_SINK_CORE_DELIVERY_H
#define CF_SINK_CORE_DELIVERY_H

/* Shared sink spine (A1) -- the pluggable delivery client interface.
 *
 * A sink's run loop (cf_sink_run / cf_sink_consumer) delivers a batch of
 * transformed items through a cf_sink_delivery_t, decoupling the consume ->
 * transform -> batch -> ack machinery from *how* the bytes reach the
 * destination. The Splunk sinks plug in the libcurl HEC client
 * (cf_hec_client_as_delivery, see cf_sink_hec.h); a future ClickHouse sink
 * supplies its own implementation (batched INSERT) without touching the spine.
 *
 * The send_batch contract is exactly cf_hec_client_send_batch's: deliver
 * `items`, set delivered[i]=1 for items that got a 2xx, poison[i]=1 for items
 * to be dead-lettered with a malloc'd poison_errs[i] the caller frees.
 * Retryable failures are retried internally (the shared retry/bisection helper
 * in cf_sink_httpdeliver.h implements the policy over a post-once primitive)
 * and never surface. Returns 0. */

#include <stddef.h>
#include <stdint.h>

#include "cf_sink_hec.h" /* cf_batch_item_t */

typedef struct cf_sink_delivery {
    void *ctx;
    /* Same contract as cf_hec_client_send_batch: deliver `items`; set
     * delivered[i]=1 on 2xx, poison[i]=1 for items to dead-letter with a
     * malloc'd poison_errs[i] (caller frees). Retryable failures are
     * retried internally and never surface. Returns 0. */
    int (*send_batch)(void *ctx, const cf_batch_item_t *items, size_t n,
                      uint8_t *delivered, uint8_t *poison, char **poison_errs);
    void (*free)(void *ctx);
} cf_sink_delivery_t;

#endif
