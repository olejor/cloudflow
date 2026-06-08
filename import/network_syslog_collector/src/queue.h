#ifndef __QUEUE_H__
#define __QUEUE_H__

#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <netinet/in.h>

/*
 * This is how we calculate message size:
 *   ethernet MTU is 1518 bytes
 *   ethernet header size is 14 bytes (without VLAN tag)
 *   IPv4 header size is 20 bytes minimum
 *   IPv6 header size is 40 bytes (fixed)
 *   UDP header size is 8 bytes
 *   1 byte for ending '\0'
 *
 * 1518 - 14 - MIN(20, 40) - 8 + 1 = 1477 bytes
 */
#define QUEUE_MESSAGE_SIZE (1518 - 14 - 20 - 8 + 1)

struct queue_element_header {
	double timestamp;
	struct {
		uint8_t ip6;
		union {
			struct in_addr ip4_addr;
			struct in6_addr ip6_addr;
		} addr;
	} host;
	struct {
		uint8_t stream;
	} redis;
};

struct queue_element_message {
	char data[QUEUE_MESSAGE_SIZE];
	uint16_t len;
};

struct queue_element {
	struct queue_element_header hdr;
	struct queue_element_message msg;
} __attribute__((aligned(sizeof(unsigned long))));

struct queue {
	struct queue_element *ring;
	atomic_ulong head;
	atomic_ulong tail;
	unsigned long size;
};

int queue_init(struct queue *q, size_t size);
void queue_free(struct queue *q);
int queue_push(struct queue *q, const struct queue_element_header *hdr, const char *data, size_t len);
int queue_pop(struct queue *q, struct queue_element_header *hdr, char *data, size_t *len);
unsigned long queue_length(const struct queue *q);
unsigned long queue_allocated_size(const struct queue *q);
double queue_usage_percent(const struct queue *q);

#endif
