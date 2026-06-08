#ifndef __STATS_H__
#define __STATS_H__

#include <stdatomic.h>

#include "config.h"

#define ATOMIC_STORE(var, n)		atomic_store(&(var), (n))
#define ATOMIC_ADD(var, n)		atomic_fetch_add(&(var), (n))
#define ATOMIC_INC(var)			atomic_fetch_add(&(var), 1)
#define ATOMIC_READ(var)		atomic_load(&(var))
#define ATOMIC_READ_AND_ZERO(var)	atomic_exchange(&(var), 0)

struct stats {
	struct {
		atomic_ulong tp_packets;
		atomic_ulong tp_drops;
		atomic_ulong tp_freeze_q_cnt;
		atomic_ulong bytes;
		atomic_ulong overflow;
	} rx_ring;
	struct {
		atomic_ulong messages;
		atomic_ulong matched;
		struct {
			atomic_ulong used;
			atomic_ulong matched;
		} rules[128]; /* max number of rules for which stats are collected */
	} filter;
	struct {
		atomic_ulong bytes;
		atomic_ulong messages;
		atomic_ulong handling_time;
		atomic_ulong retry;
		atomic_ulong drops;
	} redis[REDIS_THREADS_MAX];
};

/*
 * Blocking function that shows stats in a loop until stop is notified.
 */
void stats_loop(void);

#endif
