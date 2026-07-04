#ifndef CF_LOG_H
#define CF_LOG_H

#include <stddef.h>
#include <stdint.h>

/* Structured logging: one JSON object per line on stderr, per
 * docs/architecture.md Convention 7. Every line has at minimum
 * "ts" (RFC3339 UTC), "level", "service", and "msg", plus whatever
 * key/value pairs the caller passes.
 *
 * Shape of cf_log(): the varargs are a NULL-terminated list of alternating
 * `const char *key, const char *value` pairs, e.g.
 *
 *   cf_log(CF_LOG_INFO, "queue full", "queue", "rx", "policy", "drop_newest",
 *          NULL);
 *
 * This keeps the call site free of format strings (nothing to get wrong
 * with %-specifiers) and keeps cf_log() itself allocation-free: it renders
 * directly into a fixed-size stack buffer and writes it in one shot.
 *
 * Values are always strings. Callers logging integers render them into a
 * small caller-owned buffer first with cf_log_i64()/cf_log_u64() (also
 * allocation-free -- they format into the buffer you provide) and pass the
 * resulting pointer as the value, e.g.
 *
 *   char buf[32];
 *   cf_log(CF_LOG_INFO, "packets observed",
 *          "count", cf_log_u64(buf, sizeof(buf), count), NULL);
 *
 * If a line would not fit in the internal buffer, whole trailing key/value
 * fields are dropped silently (never a partial field, so the output stays
 * valid JSON) rather than allocating -- logging must never be a source of
 * unbounded memory growth on the hot path.
 */

typedef enum {
    CF_LOG_DEBUG = 0,
    CF_LOG_INFO,
    CF_LOG_WARN,
    CF_LOG_ERROR,
} cf_log_level_t;

/* Sets the "service" field emitted on every subsequent log line. Not
 * thread-safe; call once at startup before spawning threads. */
void cf_log_init(const char *service_name);

/* Emit one structured JSON log line to stderr. `key`/`value` pairs follow
 * `msg`, terminated by a single NULL sentinel (not a NULL key/value pair).
 */
void cf_log(cf_log_level_t level, const char *msg, ...);

/* Render an int64_t/uint64_t into `buf` (of size `buf_len`) as a decimal
 * string and return `buf`, for use as a cf_log() value argument. No
 * allocation; truncates safely if buf is too small. */
const char *cf_log_i64(char *buf, size_t buf_len, int64_t value);
const char *cf_log_u64(char *buf, size_t buf_len, uint64_t value);

#endif
