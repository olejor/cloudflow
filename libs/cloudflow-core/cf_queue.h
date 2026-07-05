#ifndef CF_QUEUE_H
#define CF_QUEUE_H

#include <stddef.h>
#include <stdatomic.h>

// Simple bounded SPSC queue. One producer and one consumer only.
typedef struct {
    unsigned char *storage;
    size_t element_size;
    size_t capacity;
    atomic_size_t head;
    atomic_size_t tail;
} cf_queue_t;

int cf_queue_init(cf_queue_t *queue, size_t capacity, size_t element_size);
void cf_queue_destroy(cf_queue_t *queue);
int cf_queue_push(cf_queue_t *queue, const void *element);
int cf_queue_pop(cf_queue_t *queue, void *element);
// Discard the oldest queued element without copying it out (advances tail).
// Same consumer-side contract as cf_queue_pop: only the single consumer --
// or, for a drop_oldest producer that is evicting to make room, that lone
// producer -- may call it. Returns 0 if one element was dropped, 1 if the
// queue was empty, -1 on invalid arguments. Useful for drop-oldest eviction,
// where copying the victim into a scratch buffer just to discard it is waste.
int cf_queue_drop(cf_queue_t *queue);
// Returns the number of elements currently queued. When called concurrently
// with the producer and/or consumer thread this is an approximate snapshot:
// head and tail are loaded with acquire ordering (each pairs with the
// matching release store, so the read is never garbage), but nothing
// prevents either index from advancing between the two loads. A torn read of
// the two indices can make the result either lower or higher than any count
// the queue actually held -- if tail (loaded second) has raced past the
// already-loaded head, the wraparound branch reports a near-capacity value.
// Treat it as a rough gauge for metrics/logging only, never as a precondition
// for correctness (push/pop already do their own full/empty checks atomically).
size_t cf_queue_length(const cf_queue_t *queue);
size_t cf_queue_capacity(const cf_queue_t *queue);

#endif
