#include <time.h>

#include "utils.h"

int ts_from_now(struct timespec *ts)
{
	return clock_gettime(CLOCK_MONOTONIC, ts);
}

unsigned long ts_diff_ms(const struct timespec *t1)
{
	struct timespec t2;

	clock_gettime(CLOCK_MONOTONIC, &t2);

	return (t2.tv_sec - t1->tv_sec) * 1000ULL + (t2.tv_nsec - t1->tv_nsec) / 1000000LL;
}

unsigned long ts_diff_us(const struct timespec *t1)
{
	struct timespec t2;

	clock_gettime(CLOCK_MONOTONIC, &t2);

	return (t2.tv_sec - t1->tv_sec) * 1000000ULL + (t2.tv_nsec - t1->tv_nsec) / 1000LL;
}

unsigned long ts_diff_ns(const struct timespec *t1)
{
	struct timespec t2;

	clock_gettime(CLOCK_MONOTONIC, &t2);

	return (t2.tv_sec - t1->tv_sec) * 1000000000ULL + (t2.tv_nsec - t1->tv_nsec);
}

int sleep_ns(unsigned long sec, unsigned long nsec)
{
	struct timespec ts = {
		.tv_sec = sec,
		.tv_nsec = nsec
	};

	/* nsec must be in the range [0, 999999999], see nanosleep() man page */

	/* we don't care about signals interrupting nanosleep() */
	return nanosleep(&ts, NULL);
}
