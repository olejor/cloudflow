#ifndef CF_SINK_CORE_DEADLETTER_H
#define CF_SINK_CORE_DEADLETTER_H

/* Shared sink spine (A1) -- dead-letter stream writer.
 *
 * The dead-letter stream name is a per-sink config value (the event sink uses
 * cloudflow:v1:deadletter:sink-splunk). XADD MAXLEN ~ 100000, entry fields
 * reason/origin_stream/origin_id/error/payload (docs/splunk-output.md,
 * "Dead-letter stream"). The XADD must succeed before the caller XACKs the
 * origin entry: cf_deadletter_write returns 0 only on a confirmed write, and
 * the caller must not ack on failure (the origin stays pending -> retried;
 * at-least-once, never silent loss). */

#include <stddef.h>
#include <stdint.h>

#include <hiredis/hiredis.h>

#include "cf_sink_stats.h"

#define CF_DEADLETTER_MAXLEN 100000
#define CF_DEADLETTER_REASON_DECODE_ERROR "decode_error"
#define CF_DEADLETTER_REASON_HEC_REJECTED "hec_rejected"

/* Returns 0 on a confirmed XADD, -1 otherwise. Writes to the dead-letter
 * stream named by `deadletter_stream`. `payload`/`payload_len` are written
 * verbatim (binary-safe). */
int cf_deadletter_write(redisContext *ctx, cf_stats_t *stats, const char *deadletter_stream,
                        const char *reason, const char *origin_stream, const char *origin_id,
                        const char *error, const uint8_t *payload, size_t payload_len);

#endif
