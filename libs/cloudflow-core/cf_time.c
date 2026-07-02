#include "cf_time.h"

#include <time.h>

int64_t cf_now_unix_nano(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);

    return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
}

int64_t cf_now_mono_nano(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
}

void cf_sleep_ns(int64_t ns)
{
    struct timespec ts;

    if (ns <= 0)
        return;

    ts.tv_sec = ns / 1000000000LL;
    ts.tv_nsec = ns % 1000000000LL;

    /* We don't care about signals interrupting nanosleep(), same as the
     * legacy sleep_ns() this is adapted from. */
    nanosleep(&ts, NULL);
}
