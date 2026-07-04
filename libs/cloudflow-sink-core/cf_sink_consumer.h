#ifndef CF_SINK_CORE_CONSUMER_H
#define CF_SINK_CORE_CONSUMER_H

/* Shared sink spine (A1) -- Redis consumer-group logic (hiredis), generic
 * over the destination transform.
 *
 * docs/splunk-output.md, "Consumer behavior":
 *  - XGROUP CREATE <stream> <group> 0 MKSTREAM per stream (BUSYGROUP ignored);
 *  - reclaim stale pending entries first (XAUTOCLAIM min-idle 60s), then
 *    XREADGROUP COUNT read_count [BLOCK block_ms] ... > ;
 *  - validate each entry's encoding/schema fields, protobuf-unpack the
 *    payload; any decode failure is dead-lettered (reason=decode_error) then
 *    XACKed;
 *  - the sink-supplied transform callback renders the unpacked event into HEC
 *    payload bytes; those are batched; entries are XACKed only after their
 *    batch got a 2xx (or after confirmed dead-lettering, reason=hec_rejected);
 *  - SIGTERM (via cf_stop_notified): flush the in-flight batch once, ack what
 *    succeeded, exit. */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <hiredis/hiredis.h>

#include "cf_sink_config.h"
#include "cf_sink_delivery.h" /* cf_sink_delivery_t, cf_batch_item_t (via cf_sink_hec.h) */
#include "cf_sink_stats.h"

#include "cloudflow/v1/envelope.pb-c.h"

#define CF_CONSUMER_DEFAULT_MIN_IDLE_MS 60000

/* Growable byte accumulator the transform appends its HEC payload bytes to.
 * Always kept NUL-terminated. */
typedef struct {
    char *data;
    size_t len;
    size_t cap;
} cf_sink_buf_t;

/* Append `n` bytes of `s` to the buffer. Returns 0 on success, -1 on OOM. */
int cf_sink_buf_append(cf_sink_buf_t *b, const char *s, size_t n);
void cf_sink_buf_reset(cf_sink_buf_t *b);
void cf_sink_buf_free(cf_sink_buf_t *b);

/* Append this event's HEC payload object(s) to `out` (newline-delimited JSON
 * the HEC client POSTs; no trailing newline). `source_stream` is the Redis
 * stream the entry came from (the transform may use it as the `source`).
 * Return 0 on success, non-zero to dead-letter (poison). */
typedef int (*cf_sink_transform_fn)(void *user, const Cloudflow__V1__CloudFlowEvent *ev,
                                     const char *source_stream, cf_sink_buf_t *out);

typedef struct {
    char *stream;
    char *entry_id;
    char *line;
    uint8_t *payload;
    size_t payload_len;
} cf_consumer_batch_item_t;

typedef struct {
    redisContext *ctx;
    const cf_sink_config_t *cfg;
    cf_stats_t *stats;

    cf_sink_transform_fn transform;
    void *transform_user;

    int stdout_mode;     /* 1 = print lines; 0 = deliver via `delivery` */
    FILE *stdout_stream; /* used in stdout mode; default stdout */
    const cf_sink_delivery_t *delivery; /* used in delivery (non-stdout) mode */

    long long min_idle_ms; /* XAUTOCLAIM min-idle; default 60000 */

    cf_consumer_batch_item_t *batch;
    size_t batch_len;
    size_t batch_cap;
    int64_t last_flush_mono_ns;
    int64_t last_lag_sample_mono_ns; /* redis_stream_lag sampling cadence */

    char **autoclaim_cursors; /* one per configured stream */
} cf_consumer_t;

/* Initialize against an established redis context. Defaults: stdout mode off,
 * stdout stream = stdout, min_idle 60s. Returns 0 on success. */
int cf_consumer_init(cf_consumer_t *c, redisContext *ctx, const cf_sink_config_t *cfg,
                     cf_stats_t *stats);

/* Set the transform callback (required before running). */
void cf_consumer_set_transform(cf_consumer_t *c, cf_sink_transform_fn fn, void *user);

void cf_consumer_set_stdout(cf_consumer_t *c, FILE *stream);
void cf_consumer_set_delivery(cf_consumer_t *c, const cf_sink_delivery_t *delivery);
void cf_consumer_set_min_idle_ms(cf_consumer_t *c, long long ms);

int cf_consumer_ensure_groups(cf_consumer_t *c);
int cf_consumer_run_once(cf_consumer_t *c);
int cf_consumer_run_forever(cf_consumer_t *c);

void cf_consumer_free(cf_consumer_t *c);

#endif
