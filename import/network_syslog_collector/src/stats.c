#include <stdio.h>
#include <unistd.h>
#include <time.h>

#include "config.h"
#include "sync.h"
#include "rx-ring.h"
#include "redis.h"
#include "utils.h"
#include "stats.h"

extern struct config config;
extern struct redis_thread redis_threads[];

struct stats stats;


static void print_rx_ring_stats(void)
{
	unsigned long bytes = ATOMIC_READ_AND_ZERO(stats.rx_ring.bytes);
	unsigned long overflow = ATOMIC_READ_AND_ZERO(stats.rx_ring.overflow);

	read_rx_ring_packet_stats();

	printf("[rx-ring] %.1f k pkts/s, %.1f Mbit/s, %lu drops, %lu freeze, %lu overflow\n",
		(double)stats.rx_ring.tp_packets / 1000,
		(double)(bytes * 8) / (1024 * 1024),
		stats.rx_ring.tp_drops,
		stats.rx_ring.tp_freeze_q_cnt,
		overflow
	);
}

static void print_filter_stats(void)
{
	unsigned long messages = ATOMIC_READ_AND_ZERO(stats.filter.messages);
	unsigned long matched = ATOMIC_READ_AND_ZERO(stats.filter.matched);

	double accepted;
	double rejected;
	double accepted_p;
	double rejected_p;

	/*
	 * matched is read a tiny bit later than messages so at high speeds
	 * it can sometimes be higher
	 */
	if (matched > messages)
		matched = messages;

	accepted = matched;
	rejected = messages - matched;

	if (messages) {
		accepted_p = ((double)matched / messages) * 100;
		rejected_p = 100 - accepted_p;
	} else {
		accepted_p = 0;
		rejected_p = 0;
	}

	printf("[filter] %.1f %% (%.1f k) accepted / %.1f %% (%.1f k) rejected\n",
		accepted_p,
		accepted / 1000,
		rejected_p,
		rejected / 1000
	);

	if (!config.verbose)
		return;

	for (int i = 0; i < ARRAY_SIZE(stats.filter.rules); i++) {
		unsigned long rule_used = ATOMIC_READ(stats.filter.rules[i].used);
		unsigned long rule_matched;
		double rule_matched_k;

		if (!rule_used)
			break;

		rule_matched = ATOMIC_READ_AND_ZERO(stats.filter.rules[i].matched);

		accepted_p = ((double)rule_matched / (messages + 1)) * 100;
		rule_matched_k = (double)rule_matched / 1000;

		printf("[filter]    rule %d  %4.1f %% / %5.1f k\n", i, accepted_p, rule_matched_k);
	}

	printf("[filter]    drop    %4.1f %% / %5.1f k\n", rejected_p, rejected / 1000);
}

static void print_redis_stats(void)
{
	for (int i = 0; i < MIN(REDIS_THREADS_MAX, config.redis_threads); i++) {
		const struct redis_thread *rt = &redis_threads[i];

		unsigned long messages = ATOMIC_READ_AND_ZERO(stats.redis[i].messages);
		unsigned long bytes = ATOMIC_READ_AND_ZERO(stats.redis[i].bytes);
		unsigned long handling_time = ATOMIC_READ_AND_ZERO(stats.redis[i].handling_time);
		unsigned long retry = ATOMIC_READ_AND_ZERO(stats.redis[i].retry);
		unsigned long drops = ATOMIC_READ_AND_ZERO(stats.redis[i].drops);

		if (!retry && !drops) {
			printf("[redis-%d] %.1f k msg/s, %.1f Mbit/s, qlen %lu/%lu %.1f%%, %.1f us/msg\n",
				rt->id,
				(double)messages / 1000,
				((double)bytes * 8) / (1024 * 1024),
				queue_length(&rt->queue),
				rt->queue.size,
				queue_usage_percent(&rt->queue),
				(double)handling_time / (messages + 1)
			);
		} else if (drops) {
			printf("[redis-%d] dropping oldest messages, qlen %lu/%lu %02.1f%%\n",
				rt->id,
				queue_length(&rt->queue),
				rt->queue.size,
				queue_usage_percent(&rt->queue)
			);
		} else if (retry) {
			printf("[redis-%d] retry: unable to send messages, qlen %lu/%lu %02.1f%%\n",
				rt->id,
				queue_length(&rt->queue),
				rt->queue.size,
				queue_usage_percent(&rt->queue)
			);
		}
	}
}

void stats_loop(void)
{
	struct timespec ts;

	ts_from_now(&ts);

	while (!stop_notified()) {
		sleep_ns(1, 0);

		if (!config.stats)
			continue;

		print_rx_ring_stats();
		print_filter_stats();
		print_redis_stats();
	}
}
