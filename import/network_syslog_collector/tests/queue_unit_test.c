#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "queue.h"


static void queue_init_tests(void)
{
	int ret;
	struct queue q;
	unsigned long length;
	unsigned long allocated_size;
	double usage;

	/* initialize the queue and do basic checks */

	ret = queue_init(&q, 4);
	CU_ASSERT(ret == 0);

	length = queue_length(&q);
	CU_ASSERT(length == 0);

	allocated_size = queue_allocated_size(&q);
	CU_ASSERT(allocated_size > 0);

	usage = queue_usage_percent(&q);
	CU_ASSERT(usage == 0.0);

	queue_free(&q);
}

static int push_element(struct queue *q, int id)
{
	struct queue_element_header hdr = {
		.timestamp = 1.23456,
		.host = {
			.ip6 = 1,
			.addr.ip4_addr.s_addr = 127,
		},
		.redis = {
			.stream = id + 1,
		}
	};
	const char *data = "queue test";
	int len = strlen(data);

	/*
	 * push element with a pattern that we can check later when we pop it
	 */
	return queue_push(q, &hdr, data, len);
}

static int pop_element(struct queue *q, int id)
{
	int ret;
	struct queue_element_header hdr;
	char data[QUEUE_MESSAGE_SIZE];
	size_t len = 0;

	ret = queue_pop(q, &hdr, data, &len);
	CU_ASSERT(ret == 0);

	/* check for the pattern that we expect */

	CU_ASSERT(hdr.timestamp == 1.23456);
	CU_ASSERT(hdr.host.ip6 == 1);
	CU_ASSERT(hdr.host.addr.ip4_addr.s_addr == 127);
	CU_ASSERT(hdr.redis.stream == id + 1);

	data[len] = '\0';
	CU_ASSERT(strcmp(data, "queue test") == 0);
	CU_ASSERT(len == strlen("queue test"));

	return ret;
}


static void queue_push_pop_tests(void)
{
	int ret;
	struct queue q;

	ret = queue_init(&q, 4);
	CU_ASSERT(ret == 0);
	CU_ASSERT(queue_length(&q) == 0);
	CU_ASSERT(queue_usage_percent(&q) == 0.0);

	ret = push_element(&q, 1);
	CU_ASSERT(ret == 0);
	CU_ASSERT(queue_length(&q) == 1);
	CU_ASSERT(queue_usage_percent(&q) == 25.0);

	ret = push_element(&q, 2);
	CU_ASSERT(ret == 0);
	CU_ASSERT(queue_length(&q) == 2);
	CU_ASSERT(queue_usage_percent(&q) == 50.0);

	ret = pop_element(&q, 1);
	CU_ASSERT(ret == 0);
	CU_ASSERT(queue_length(&q) == 1);
	CU_ASSERT(queue_usage_percent(&q) == 25.0);

	ret = pop_element(&q, 2);
	CU_ASSERT(ret == 0);
	CU_ASSERT(queue_length(&q) == 0);
	CU_ASSERT(queue_usage_percent(&q) == 0.0);

	queue_free(&q);
}

static void queue_ring_tests(void)
{
	int ret;
	struct queue q;

	ret = queue_init(&q, 4);
	CU_ASSERT(ret == 0);
	CU_ASSERT(queue_length(&q) == 0);
	CU_ASSERT(queue_usage_percent(&q) == 0.0);

	/*
	 * test with more elements than queue size so that all elements in
	 * the ring are used and head/tail wrap around
	 */
	for (int i = 0; i < 20; i++) {
		ret = push_element(&q, i);
		CU_ASSERT(ret == 0);

		ret = pop_element(&q, i);
		CU_ASSERT(ret == 0);
	}

	CU_ASSERT(queue_length(&q) == 0);
	CU_ASSERT(queue_usage_percent(&q) == 0.0);

	queue_free(&q);
}

int main(void)
{
	CU_ErrorCode cret;
	CU_pSuite psuite;
	CU_pTest ptest;

	cret = CU_initialize_registry();
	if (cret != CUE_SUCCESS)
		return CU_get_error();

	psuite = CU_add_suite("Logchewie Queue Suite", 0, 0);
	if (psuite == NULL) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	ptest = CU_add_test(psuite, "Queue init tests", queue_init_tests);
	if (ptest == NULL) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	ptest = CU_add_test(psuite, "Queue push pop tests", queue_push_pop_tests);
	if (ptest == NULL) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	ptest = CU_add_test(psuite, "Queue ring tests", queue_ring_tests);
	if (ptest == NULL) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();

	CU_cleanup_registry();

	return 0;
}
