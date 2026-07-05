// Bounded single-producer/single-consumer ring buffer.
//
// Memory ordering (WP-04). This is the only concurrency primitive in the
// source pipeline (D4), so its head/tail synchronization has to be correct
// on architectures with weaker memory models than x86, not just "happens to
// work" under x86's strong ordering. The queue has exactly one thread that
// ever writes `head` (the producer) and exactly one that ever writes `tail`
// (the consumer), so each thread may load its *own* index with
// memory_order_relaxed -- nothing but that thread ever changes it, so a
// stale value cannot be observed. Cross-thread synchronization is carried
// entirely by the *other* index, via two independent release/acquire
// pairings:
//
//   1. Producer writes storage[head], then
//      atomic_store_explicit(&head, next, memory_order_release).
//      Consumer does atomic_load_explicit(&head, memory_order_acquire)
//      before reading storage[tail]. The acquire load, if it observes the
//      producer's new head value (or any later one -- head is monotonic
//      modulo capacity, so a later release also carries this one via the
//      release sequence), synchronizes-with that release store. That makes
//      the producer's memcpy into storage happen-before the consumer's
//      memcpy out of it: the consumer can never observe a torn or stale
//      element.
//
//   2. Symmetrically, consumer reads storage[tail], then
//      atomic_store_explicit(&tail, ..., memory_order_release). Producer
//      does atomic_load_explicit(&tail, memory_order_acquire) before
//      deciding whether the queue is full and writing storage[head]. This
//      makes the consumer's read of a slot happen-before the producer's
//      later overwrite of that same slot once it comes back around the
//      ring, which is what makes it safe to reuse the memory at all.
//
// Together these two pairings give the queue the same guarantees as a
// mutex-protected buffer without the mutex: every element is fully written
// before it is read, and never overwritten before it is read.
#include "cf_queue.h"

#include <stdlib.h>
#include <string.h>

int cf_queue_init(cf_queue_t *queue, size_t capacity, size_t element_size)
{
    if (!queue || capacity < 2 || element_size == 0)
        return -1;

    queue->storage = calloc(capacity, element_size);
    if (!queue->storage)
        return -1;

    queue->element_size = element_size;
    queue->capacity = capacity;
    atomic_store(&queue->head, 0);
    atomic_store(&queue->tail, 0);

    return 0;
}

void cf_queue_destroy(cf_queue_t *queue)
{
    if (!queue)
        return;

    free(queue->storage);
    queue->storage = NULL;
    queue->element_size = 0;
    queue->capacity = 0;
    atomic_store(&queue->head, 0);
    atomic_store(&queue->tail, 0);
}

int cf_queue_push(cf_queue_t *queue, const void *element)
{
    size_t head;
    size_t next;
    size_t tail;

    if (!queue || !queue->storage || !element)
        return -1;

    /* Own index: only this thread ever writes head, so relaxed is enough. */
    head = atomic_load_explicit(&queue->head, memory_order_relaxed);
    next = (head + 1) % queue->capacity;
    /* Pairing 2: acquire the consumer's tail release so that its prior read
     * of storage[head] (from the last time the ring wrapped this far)
     * happens-before we overwrite that slot below. */
    tail = atomic_load_explicit(&queue->tail, memory_order_acquire);

    if (next == tail)
        return 1;

    memcpy(queue->storage + (head * queue->element_size), element, queue->element_size);
    /* Pairing 1: publish the element with release, after the memcpy, so the
     * consumer's acquire load of head (below, in cf_queue_pop) cannot
     * observe the new head without also observing this write. */
    atomic_store_explicit(&queue->head, next, memory_order_release);

    return 0;
}

int cf_queue_pop(cf_queue_t *queue, void *element)
{
    size_t head;
    size_t tail;

    if (!queue || !queue->storage || !element)
        return -1;

    /* Own index: only this thread ever writes tail, so relaxed is enough. */
    tail = atomic_load_explicit(&queue->tail, memory_order_relaxed);
    /* Pairing 1: acquire the producer's head release so its memcpy into
     * storage[tail] happens-before we read it below. */
    head = atomic_load_explicit(&queue->head, memory_order_acquire);

    if (tail == head)
        return 1;

    memcpy(element, queue->storage + (tail * queue->element_size), queue->element_size);
    /* Pairing 2: publish the freed slot with release, after the memcpy-out,
     * so the producer's acquire load of tail (above, in cf_queue_push)
     * cannot observe the advanced tail without also observing that this
     * read has completed -- only then is it safe to overwrite the slot. */
    atomic_store_explicit(&queue->tail, (tail + 1) % queue->capacity, memory_order_release);

    return 0;
}

int cf_queue_drop(cf_queue_t *queue)
{
    size_t head;
    size_t tail;

    if (!queue || !queue->storage)
        return -1;

    /* Own index: only the consumer (or a drop_oldest producer evicting to make
     * room) ever writes tail, so relaxed is enough. */
    tail = atomic_load_explicit(&queue->tail, memory_order_relaxed);
    head = atomic_load_explicit(&queue->head, memory_order_acquire);

    if (tail == head)
        return 1;

    /* No memcpy-out: we are discarding the slot, so nothing reads it. The
     * release store still pairs with the producer's acquire load of tail
     * (Pairing 2 in cf_queue_push) so the slot is safe to overwrite. */
    atomic_store_explicit(&queue->tail, (tail + 1) % queue->capacity, memory_order_release);

    return 0;
}

size_t cf_queue_length(const cf_queue_t *queue)
{
    size_t head;
    size_t tail;

    if (!queue || !queue->storage || queue->capacity == 0)
        return 0;

    head = atomic_load_explicit(&queue->head, memory_order_acquire);
    tail = atomic_load_explicit(&queue->tail, memory_order_acquire);

    if (head >= tail)
        return head - tail;

    return queue->capacity - (tail - head);
}

size_t cf_queue_capacity(const cf_queue_t *queue)
{
    if (!queue || queue->capacity == 0)
        return 0;

    return queue->capacity - 1;
}
