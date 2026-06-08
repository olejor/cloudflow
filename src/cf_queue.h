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
size_t cf_queue_length(const cf_queue_t *queue);
size_t cf_queue_capacity(const cf_queue_t *queue);

#endif
