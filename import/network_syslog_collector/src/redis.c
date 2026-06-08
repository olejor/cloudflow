#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <ctype.h>

#include <hiredis_cluster/hircluster.h>
#include <yyjson.h>

#include "config.h"
#include "sync.h"
#include "redis.h"
#include "queue.h"
#include "filter.h"
#include "stats.h"
#include "utils.h"


#define DO_NOT_SEND_TO_REDIS 0

#define PFX "[redis] "


struct redis_thread redis_threads[REDIS_THREADS_MAX];

extern struct config config;
extern struct stats stats;

typedef struct {
	stream_id_e stream;
	char *json;
} pipeline_buf[REDIS_PIPELINE_SIZE];


int redis_queue_push(struct queue_element_header *hdr, const char *data, size_t len)
{
	struct queue *q;
	static unsigned int num = 0;

	/* round robin */
	q = &redis_threads[num++ % config.redis_threads].queue;

	return queue_push(q, hdr, data, len);
}

static void print_redis_cluster_error(redisClusterContext *ctx, const char *func)
{
	if (ctx->err)
		fprintf(stderr, "%s failed: %s\n", func, ctx->errstr);
	else
		fprintf(stderr, "%s failed\n", func);
}

static redisClusterContext *redis_cluster_connect(const char *servers, int verbose)
{
	redisClusterContext *ctx;
	int ret;
	struct timeval timeout = {
		.tv_sec = 3,
	};

	ctx = redisClusterContextInit();
	if (!ctx) {
		if (verbose)
			fprintf(stderr, "redisClusterContextInit() failed: can't allocate context\n");
		return NULL;
	}

	ret = redisClusterSetOptionAddNodes(ctx, servers);
	if (ret != REDIS_OK) {
		if (verbose)
			print_redis_cluster_error(ctx, "redisClusterSetOptionAddNodes()");
		goto err;
	}

	ret = redisClusterSetOptionConnectTimeout(ctx, timeout);
	if (ret != REDIS_OK) {
		if (verbose)
			print_redis_cluster_error(ctx, "redisClusterSetOptionConnectTimeout()");
		goto err;
	}

	ret = redisClusterSetOptionRouteUseSlots(ctx);
	if (ret != REDIS_OK) {
		if (verbose)
			print_redis_cluster_error(ctx, "redisClusterSetOptionRouteUseSlots()");
		goto err;
	}

	ret = redisClusterConnect2(ctx);
	if (ret != REDIS_OK) {
		if (verbose)
			print_redis_cluster_error(ctx, "redisClusterConnect2()");
		goto err;
	}

	return ctx;

err:
	redisClusterFree(ctx);
	return NULL;
}

static void redis_cluster_disconnect(redisClusterContext *ctx)
{
	redisClusterFree(ctx);
}

static redisClusterContext *redis_cluster_reconnect(redisClusterContext *ctx, const char *servers)
{
	redisClusterFree(ctx);

	return redis_cluster_connect(servers, 0);
}

static void sanitize_message(char *message, size_t len)
{
	/* message is not \0 terminated and we have space to put \0 at the end */
	message[len] = '\0';

	for (unsigned long i = 0; i < len; i++) {
		if (likely(isprint(message[i])))
			continue;
		else
			message[i] = '.';
	}
}

static int message_to_json(const struct queue_element_header *hdr, const char *message, char **json)
{
	char buf[INET6_ADDRSTRLEN];
	const char *addr;
	yyjson_mut_doc *doc;
	yyjson_mut_val *root;
	int ret;

	if (!hdr->host.ip6)
		addr = inet_ntop(AF_INET, &hdr->host.addr.ip4_addr, buf, sizeof(buf));
	else
		addr = inet_ntop(AF_INET6, &hdr->host.addr.ip6_addr, buf, sizeof(buf));

	ASSERT(addr);
	if (!addr)
		return 1;

	doc = yyjson_mut_doc_new(NULL);
	ASSERT(doc);
	if (!doc)
		return 1;

	root = yyjson_mut_obj(doc);
	ASSERT(root);
	if (!root)
		goto err;

	yyjson_mut_doc_set_root(doc, root);

	ret = yyjson_mut_obj_add_int(doc, root, "version", 1);
	ASSERT(ret);
	if (!ret)
		goto err;

	ret = yyjson_mut_obj_add_str(doc, root, "raddr", addr);
	ASSERT(ret);
	if (!ret)
		goto err;

	ret = yyjson_mut_obj_add_real(doc, root, "ts", hdr->timestamp);
	ASSERT(ret);
	if (!ret)
		goto err;

	ret = yyjson_mut_obj_add_str(doc, root, "payload", message);
	ASSERT(ret);
	if (!ret)
		goto err;

	*json = yyjson_mut_write(doc, 0, NULL);
	ASSERT(*json);
	if (!*json)
		goto err;

	yyjson_mut_doc_free(doc);

	return 0;

err:
	yyjson_mut_doc_free(doc);

	return 1;
}

#if 0
/*
 * a hack to get more redis streams so that we can distribute traffic
 * across cluster nodes
 */
#undef GET_STREAM
static const char *GET_STREAM(int arg)
{
	static _Thread_local unsigned int id = 0;

	/*
	 * these stream names are calculated so that each of them maps to
	 * a different shard on 16 node cluster based on this formula:
	 * (crc16(key) % 16384) / 16
	 */
	static const char *streams[] = {
		"10", // 0
		"3",  // 1
		"61", // 2
		"43", // 3
		"11", // 4
		"2",  // 5
		"60", // 6
		"42", // 7
		"12", // 8
		"1",  // 9
		"63", // 10
		"41", // 11
		"13", // 12
		"0",  // 13
		"62", // 14
		"40", // 15
	};

	(void)arg;

	return streams[id++ % ARRAY_SIZE(streams)];
}
#endif

static int redis_pipeline_send(redisClusterContext **ctx, pipeline_buf pbuf)
{
	int ret;
	int map[REDIS_PIPELINE_SIZE];
	int idx = 0;

#if DO_NOT_SEND_TO_REDIS
	/* don't send to redis - for testing purposes only */
	return 0;
#endif

	if (!*ctx)
		return 1;

	/* set map entries to -1 */
	memset(map, 0xff, sizeof(map));

	for (int i = 0; i < REDIS_PIPELINE_SIZE; i++) {
		const char *json;
		const char *stream;

		json = pbuf[i].json;
		if (!json)
			continue;

		/*
		 * store pbuf entry index in map so that later
		 * we can map response to the pbuf entry
		 */
		map[idx++] = i;

		stream = GET_STREAM(pbuf[i].stream);

		ret = redisClusterAppendCommand(*ctx, "XADD %s MAXLEN ~ %u * log %s", stream, REDIS_XADD_MAXLEN, json);
		if (ret != REDIS_OK) {
			print_redis_cluster_error(*ctx, "redisClusterAppendCommand()");
			goto err;
		}

	}

	for (int i = 0; i < REDIS_PIPELINE_SIZE; i++) {
		int idx;
		redisReply *reply = NULL;

		idx = map[i];
		if (idx == -1)
			continue;

		ret = redisClusterGetReply(*ctx, (void **)&reply);
		if (ret != REDIS_OK || !reply) {
			print_redis_cluster_error(*ctx, "redisClusterGetReply()");
			goto err;
		}

		freeReplyObject(reply);

		free(pbuf[idx].json);
		pbuf[idx].json = NULL;
	}

#if 0
	/* assert that pbuf memory was freed */
	for (int i = 0; i < REDIS_PIPELINE_SIZE; i++) {
		ASSERT(pbuf[i].json == NULL);
	}
#endif

	return 0;

err:
	/* redis cluster error so free the context */
	redis_cluster_disconnect(*ctx);
	*ctx = NULL;

	return 1;
}


static int redis_queue_handler(struct redis_thread *rt)
{
	int ret;
	size_t total_len = 0;
	pipeline_buf pbuf = { 0 };
	int pidx = 0;
	struct timespec pbuf_ts;
	struct timespec retry_ts;
	redisClusterContext *ctx;

	ctx = redis_cluster_connect(config.redis_servers, 1);
	if (!ctx)
		return 1;

	ts_from_now(&pbuf_ts);
	ts_from_now(&retry_ts);

	while (!stop_notified()) {
		struct queue_element_header hdr;
		char message[QUEUE_MESSAGE_SIZE];
		size_t len;
		struct timespec ts;

		ts_from_now(&ts);

		ret = queue_pop(&rt->queue, &hdr, message, &len);
		if (ret) {
			/*
			 * The queue is empty and we call sleep_ns() to reschedule. Other options
			 * would be to use eventfd or pthread cond signal/wait but both add
			 * complexity. We don't expect logchewie to be idle for too long so
			 * reschedule is ok here.
			 */
			sleep_ns(0, 10 * 1000 * 1000);
		} else {
			double usage;

			usage = queue_usage_percent(&rt->queue);
			if (usage >= 90) {
				/* drop oldest messages when the queue is 90% full */
				ATOMIC_INC(stats.redis[rt->id].drops);
				continue;
			}

			total_len += len;

			sanitize_message(message, len);

			pbuf[pidx].stream = hdr.redis.stream;

			ret = message_to_json(&hdr, message, &pbuf[pidx].json);
			if (ret)
				continue;

			pidx++;
		}

		/* pbuf is empty, continue */
		if (pidx == 0)
			continue;

		/* continue filling pbuf until full or 100 ms elapsed */
		if (pidx < REDIS_PIPELINE_SIZE && ts_diff_ms(&pbuf_ts) < 100)
			continue;

		pidx = 0;
		ts_from_now(&pbuf_ts);

retry:
		ret = redis_pipeline_send(&ctx, pbuf);
		if (ret) {
			/* stop processing if signalled */
			if (stop_notified())
				break;

			if (ts_diff_ms(&retry_ts) >= 1000) {
				/* try to reconnect */
				ctx = redis_cluster_reconnect(ctx, config.redis_servers);

				ts_from_now(&retry_ts);
			}

			/* throttle down on retry */
			sleep_ns(0, 1 * 1000 * 1000);

			ATOMIC_INC(stats.redis[rt->id].retry);
			goto retry;
		}

		ATOMIC_ADD(stats.redis[rt->id].handling_time, ts_diff_us(&ts));
		ATOMIC_ADD(stats.redis[rt->id].messages, REDIS_PIPELINE_SIZE);
		ATOMIC_ADD(stats.redis[rt->id].bytes, total_len);

		total_len = 0;
	}

	redis_cluster_disconnect(ctx);

	return 0;
}

static void *redis_client_thread(void *arg)
{
	int ret;
	struct redis_thread *rt = arg;
	char name[32];
	unsigned long mem_size;

	snprintf(name, sizeof(name), "redis-%d", rt->id);
	pthread_setname_np(pthread_self(), name);

	printf("[redis-%d] thread started\n", rt->id);

	mem_size = queue_allocated_size(&rt->queue);
	printf("[redis-%d] queue size %lu elements, %lu kB @ %p\n", rt->id, rt->queue.size, mem_size / 1024, &rt->queue.ring);

	ret = redis_queue_handler(rt);

	printf("[redis-%d] thread stopped\n", rt->id);

	stop_notify(ret);

	return NULL;
}

int redis_start(void)
{
	redisClusterContext *ctx;

	printf(PFX "cluster servers: %s\n", config.redis_servers);

	ctx = redis_cluster_connect(config.redis_servers, 1);
	if (!ctx) {
		fprintf(stderr, PFX "connection failed\n");
		return 1;
	}

	printf(PFX "connected\n");

	redis_cluster_disconnect(ctx);

	for (int i = 0; i < config.redis_threads; i++) {
		struct redis_thread *rt = &redis_threads[i];
		int ret;

		rt->id = i;

		ret = queue_init(&rt->queue, REDIS_THREAD_QUEUE_MESSAGES_MAX);
		if (ret) {
			fprintf(stderr, PFX "queue_init() failed: %s (%d)\n", strerror(ret), ret);
			return ret;
		}

		ret = pthread_create(&rt->thread_id, NULL, redis_client_thread, rt);
		if (ret) {
			fprintf(stderr, PFX "ptrhead_create() failed: %s\n", strerror(ret));
			return ret;
		}
	}

	return 0;
}

void redis_stop(void)
{
	for (int i = 0; i < config.redis_threads; i++) {
		struct redis_thread *rt = &redis_threads[i];
		int ret;

		ret = pthread_join(rt->thread_id, NULL);
		if (ret)
			fprintf(stderr, PFX "pthread_join() of id %d failed: %s\n", rt->id, strerror(ret));

		queue_free(&rt->queue);
	}
}
