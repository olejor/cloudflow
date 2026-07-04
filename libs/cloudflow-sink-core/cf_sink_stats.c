#include "cf_sink_stats.h"

#include "cf_log.h"
#include "cf_stats.h"
#include "cf_time.h"

void cf_stats_init(cf_stats_t *s)
{
    atomic_init(&s->splunk_delivery_total, 0);
    atomic_init(&s->splunk_delivery_errors_total, 0);
    atomic_init(&s->splunk_retry_total, 0);
    atomic_init(&s->deadletter_total, 0);
    atomic_init(&s->protobuf_decode_errors_total, 0);
    atomic_init(&s->splunk_batch_size_last, 0);
    atomic_init(&s->splunk_delivery_latency_ms_last, 0);
    atomic_init(&s->redis_stream_lag, 0);
    s->last_emit_mono_ns = cf_now_mono_nano();
}

void cf_stats_emit(cf_stats_t *s)
{
    char b1[32], b2[32], b3[32], b4[32], b5[32], b6[32], b7[32], b8[32];

    cf_log(CF_LOG_INFO, "stats",
           "splunk_delivery_total",
           cf_log_u64(b1, sizeof(b1), CF_ATOMIC_READ(s->splunk_delivery_total)),
           "splunk_delivery_errors_total",
           cf_log_u64(b2, sizeof(b2), CF_ATOMIC_READ(s->splunk_delivery_errors_total)),
           "splunk_retry_total",
           cf_log_u64(b3, sizeof(b3), CF_ATOMIC_READ(s->splunk_retry_total)),
           "deadletter_total",
           cf_log_u64(b4, sizeof(b4), CF_ATOMIC_READ(s->deadletter_total)),
           "protobuf_decode_errors_total",
           cf_log_u64(b5, sizeof(b5), CF_ATOMIC_READ(s->protobuf_decode_errors_total)),
           "splunk_batch_size",
           cf_log_u64(b6, sizeof(b6), CF_ATOMIC_READ(s->splunk_batch_size_last)),
           "splunk_delivery_latency_ms",
           cf_log_u64(b7, sizeof(b7), CF_ATOMIC_READ(s->splunk_delivery_latency_ms_last)),
           "redis_stream_lag",
           cf_log_u64(b8, sizeof(b8), CF_ATOMIC_READ(s->redis_stream_lag)),
           NULL);

    s->last_emit_mono_ns = cf_now_mono_nano();
}

void cf_stats_maybe_emit(cf_stats_t *s, int64_t interval_ms)
{
    if (cf_now_mono_nano() - s->last_emit_mono_ns >= interval_ms * 1000000LL)
        cf_stats_emit(s);
}
