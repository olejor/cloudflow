#ifndef __UTILS_H__
#define __UTILS_H__

#ifdef ENABLE_ASSERTS
#include <assert.h>
#endif

#include <time.h>

#define ARRAY_SIZE(a) ((int)(sizeof(a) / (sizeof(a[0]))))

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#define likely(x)    __builtin_expect(!!(x), 1)
#define unlikely(x)  __builtin_expect(!!(x), 0)

#ifdef ENABLE_ASSERTS
#define ASSERT(x) assert(x)
#else
#define ASSERT(x)
#endif

int ts_from_now(struct timespec *ts);
unsigned long ts_diff_ms(const struct timespec *t1);
unsigned long ts_diff_us(const struct timespec *t1);
unsigned long ts_diff_ns(const struct timespec *t1);
int sleep_ns(unsigned long sec, unsigned long nsec);

#endif
