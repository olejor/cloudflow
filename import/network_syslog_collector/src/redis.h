#ifndef __REDIS_H__
#define __REDIS_H__

#include <pthread.h>

#include "queue.h"


struct redis_thread {
	int id;
	pthread_t thread_id;
	struct queue queue;
};

int redis_start(void);
void redis_stop(void);

int redis_queue_push(struct queue_element_header *hdr, const char *data, size_t len);

#endif
