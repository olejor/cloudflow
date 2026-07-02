#ifndef CF_TIME_H
#define CF_TIME_H

#include <stdint.h>

/* Wall-clock time in nanoseconds since the Unix epoch (CLOCK_REALTIME). */
int64_t cf_now_unix_nano(void);

/* Monotonic time in nanoseconds, not tied to the epoch (CLOCK_MONOTONIC).
 * Use for measuring durations; never for wall-clock timestamps. */
int64_t cf_now_mono_nano(void);

/* Sleep for the given number of nanoseconds. Interrupted sleeps are not
 * retried -- callers that need a hard deadline should loop themselves. */
void cf_sleep_ns(int64_t ns);

#endif
