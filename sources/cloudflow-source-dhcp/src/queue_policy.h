#ifndef CF_SOURCE_DHCP_QUEUE_POLICY_H
#define CF_SOURCE_DHCP_QUEUE_POLICY_H

/* D9 backpressure policy (docs/design/00-overview.md): every cf_queue in the
 * source pipeline has an explicit on_full policy loaded from config, and
 * every drop it causes increments a named counter. This header/",.c" pair
 * is the one shared implementation of that policy, used by both the
 * rx-reader -> q_pkt push (WP-08, this WP) and the formatter -> q_evt push
 * (WP-10, a later WP) -- hence living outside rx_reader.h even though this
 * WP is the first consumer. */

#include <stdatomic.h>
#include <stddef.h>

#include "cf_queue.h"

typedef enum {
    CF_ONFULL_DROP_NEWEST = 0, /* default: skip the element being pushed, count it */
    CF_ONFULL_DROP_OLDEST,     /* pop the oldest queued element, count it, then push */
    CF_ONFULL_BLOCK,           /* bounded retry loop until room frees up or shutdown */
} cf_queue_full_policy_t;

/* Human-readable policy name, for structured log lines (cf_log). Never
 * returns NULL. */
const char *cf_queue_full_policy_name(cf_queue_full_policy_t policy);

/* Push `element` (exactly `element_size` bytes, which must match the size
 * `queue` was cf_queue_init()'d with) applying D9's on_full policy when the
 * queue is full:
 *
 *   - CF_ONFULL_DROP_NEWEST: the element being pushed is dropped;
 *     *drop_counter (if non-NULL) is incremented once.
 *   - CF_ONFULL_DROP_OLDEST: the oldest queued element is popped and
 *     discarded, *drop_counter incremented once, then `element` is pushed
 *     (this always succeeds immediately afterward under the single-producer
 *     contract cf_queue requires -- see cf_queue.h).
 *   - CF_ONFULL_BLOCK: retries push in a bounded loop, sleeping
 *     CF_QUEUE_POLICY_BLOCK_SLEEP_NS (1 ms) between attempts and checking
 *     cf_stop_notified() each iteration so shutdown is never blocked
 *     forever. If the retry budget is exhausted or shutdown is requested
 *     first, the element is dropped and *drop_counter incremented.
 *
 * Returns 0 if `element` ended up in the queue, 1 if it was dropped per
 * policy, -1 on a hard argument error (queue/element NULL, size mismatch,
 * or oversized element -- nothing pushed, drop_counter untouched).
 */
int cf_queue_push_policy(cf_queue_t *queue, const void *element, size_t element_size,
                          cf_queue_full_policy_t policy, atomic_ulong *drop_counter);

#endif
