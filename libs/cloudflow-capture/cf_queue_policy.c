#include "cf_queue_policy.h"

#include "cf_stats.h"
#include "cf_sync.h"
#include "cf_time.h"

/* Elements that ever flow through this helper are fixed-size structs from
 * cloudflow.h (cf_packet_item_t, cf_event_item_t), both well under this
 * bound. It exists so a hostile/garbage element_size can never turn the
 * drop_oldest victim buffer below into an unbounded stack allocation. */
#define CF_QUEUE_POLICY_MAX_ELEMENT_SIZE (64u * 1024u)

#define CF_QUEUE_POLICY_BLOCK_SLEEP_NS (1000L * 1000L) /* 1 ms, per the WP-08 spec */
#define CF_QUEUE_POLICY_BLOCK_MAX_RETRIES 500           /* bounded: ~0.5s worst case */

const char *cf_queue_full_policy_name(cf_queue_full_policy_t policy)
{
    switch (policy) {
    case CF_ONFULL_DROP_NEWEST:
        return "drop_newest";
    case CF_ONFULL_DROP_OLDEST:
        return "drop_oldest";
    case CF_ONFULL_BLOCK:
        return "block";
    default:
        return "unknown";
    }
}

int cf_queue_push_policy(cf_queue_t *queue, const void *element, size_t element_size,
                          cf_queue_full_policy_t policy, atomic_ulong *drop_counter)
{
    int rc;

    if (!queue || !element || element_size == 0 || element_size != queue->element_size ||
        element_size > CF_QUEUE_POLICY_MAX_ELEMENT_SIZE)
        return -1;

    rc = cf_queue_push(queue, element);
    if (rc == 0)
        return 0; /* fast path: there was room */
    if (rc < 0)
        return -1;

    /* rc == 1: queue was full at push time. Apply on_full. */
    switch (policy) {
    case CF_ONFULL_DROP_OLDEST: {
        unsigned char victim[CF_QUEUE_POLICY_MAX_ELEMENT_SIZE];

        if (cf_queue_pop(queue, victim) == 0) {
            if (drop_counter)
                CF_ATOMIC_INC(*drop_counter);

            /* Single-producer contract (cf_queue.h): we are the only thread
             * that ever pushes to this queue, and we just freed exactly one
             * slot, so this push cannot itself report "full" again. Still
             * guard defensively rather than assume. */
            rc = cf_queue_push(queue, element);
            if (rc == 0)
                return 0;
        }

        /* Either the pop raced to "empty" (shouldn't happen under SPSC) or
         * the guarded re-push above still failed: fall back to counting
         * this as a drop of the newest element too, rather than silently
         * losing accounting. */
        if (drop_counter)
            CF_ATOMIC_INC(*drop_counter);
        return 1;
    }

    case CF_ONFULL_BLOCK: {
        int retries;

        for (retries = 0; retries < CF_QUEUE_POLICY_BLOCK_MAX_RETRIES; retries++) {
            if (cf_stop_notified())
                break;

            cf_sleep_ns(CF_QUEUE_POLICY_BLOCK_SLEEP_NS);

            rc = cf_queue_push(queue, element);
            if (rc == 0)
                return 0;
            if (rc < 0)
                return -1;
        }

        if (drop_counter)
            CF_ATOMIC_INC(*drop_counter);
        return 1;
    }

    case CF_ONFULL_DROP_NEWEST:
    default:
        if (drop_counter)
            CF_ATOMIC_INC(*drop_counter);
        return 1;
    }
}
