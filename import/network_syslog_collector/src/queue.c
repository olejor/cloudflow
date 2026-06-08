#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "queue.h"
#include "utils.h"

/*
 * This code is for SPSC (single producer single consumer) scenario only.
 *
 * The idea here is to have a preallocated ring of elements where one endpoint
 * only writes advancing the head (producer), and the other endpoint only
 * reads advancing the tail (consumer).
 */

int queue_init(struct queue *q, size_t size)
{
	int ret;

	/* queue must have space for at least head and tail elements */
	ASSERT(size >= 2);

	ret = posix_memalign((void *)&(q->ring), sizeof(unsigned long), size * sizeof(struct queue_element));
	if (ret)
		return ret;

	q->head = 0;
	q->tail = 0;
	q->size = size;

	return 0;
}

void queue_free(struct queue *q)
{
	free(q->ring);
	q->head = 0;
	q->tail = 0;
	q->size = 0;
}

int queue_push(struct queue *q, const struct queue_element_header *hdr, const char *data, size_t len)
{
	unsigned long next;
	struct queue_element *e;

	ASSERT(q->size);
	ASSERT(len > 0);
	ASSERT(len <= QUEUE_MESSAGE_SIZE);

	next = (q->head + 1) % q->size;
	if (next == q->tail) /* queue is full */
		return 1;

	e = &q->ring[q->head];
	memcpy(&e->hdr, hdr, sizeof(struct queue_element_header));
	memcpy(e->msg.data, data, len);
	e->msg.len = (uint16_t)len;

	/* only producer writes to head */
	q->head = next;

	return 0;
}

int queue_pop(struct queue *q, struct queue_element_header *hdr, char *data, size_t *len)
{
	const struct queue_element *e;

	if (q->tail == q->head) /* queue is empty */
		return 1;

	e = &q->ring[q->tail];

	memcpy(hdr, &e->hdr, sizeof(struct queue_element_header));
	memcpy(data, e->msg.data, e->msg.len);
	*len = (size_t)e->msg.len;

	ASSERT(*len < QUEUE_MESSAGE_SIZE);

	/* only consumer writes to tail */
	q->tail = (q->tail + 1) % q->size;

	return 0;
}

unsigned long queue_length(const struct queue *q)
{
	if (q->head >= q->tail)
		return q->head - q->tail;
	else
		return q->size - (q->tail - q->head);
}

unsigned long queue_allocated_size(const struct queue *q)
{
	return q->size * sizeof(struct queue_element);
}

double queue_usage_percent(const struct queue *q)
{
	return ((double)queue_length(q) / q->size) * 100;
}
