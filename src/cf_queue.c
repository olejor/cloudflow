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

    head = atomic_load_explicit(&queue->head, memory_order_relaxed);
    next = (head + 1) % queue->capacity;
    tail = atomic_load_explicit(&queue->tail, memory_order_acquire);

    if (next == tail)
        return 1;

    memcpy(queue->storage + (head * queue->element_size), element, queue->element_size);
    atomic_store_explicit(&queue->head, next, memory_order_release);

    return 0;
}

int cf_queue_pop(cf_queue_t *queue, void *element)
{
    size_t head;
    size_t tail;

    if (!queue || !queue->storage || !element)
        return -1;

    tail = atomic_load_explicit(&queue->tail, memory_order_relaxed);
    head = atomic_load_explicit(&queue->head, memory_order_acquire);

    if (tail == head)
        return 1;

    memcpy(element, queue->storage + (tail * queue->element_size), queue->element_size);
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
