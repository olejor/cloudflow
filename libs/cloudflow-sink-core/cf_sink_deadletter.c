#include "cf_sink_deadletter.h"

#include <string.h>

#include "cf_log.h"
#include "cf_stats.h"

#define CF_DEADLETTER_ERROR_MAX 2000

int cf_deadletter_write(redisContext *ctx, cf_stats_t *stats, const char *deadletter_stream,
                        const char *reason, const char *origin_stream, const char *origin_id,
                        const char *error, const uint8_t *payload, size_t payload_len)
{
    redisReply *reply;
    char maxlen[24];
    char errtrunc[CF_DEADLETTER_ERROR_MAX + 1];
    int ok;

    if (!ctx || !deadletter_stream)
        return -1;

    if (!error)
        error = "";
    snprintf(errtrunc, sizeof(errtrunc), "%s", error);
    snprintf(maxlen, sizeof(maxlen), "%d", CF_DEADLETTER_MAXLEN);
    if (!payload)
        payload = (const uint8_t *)"";

    /* %b keeps reason/error/payload binary-safe. */
    reply = redisCommand(ctx,
                         "XADD %s MAXLEN ~ %s * reason %b origin_stream %b origin_id %b "
                         "error %b payload %b",
                         deadletter_stream, maxlen,
                         reason, strlen(reason),
                         origin_stream, strlen(origin_stream),
                         origin_id, strlen(origin_id),
                         errtrunc, strlen(errtrunc),
                         payload, payload_len);

    ok = (reply && reply->type != REDIS_REPLY_ERROR);
    if (reply)
        freeReplyObject(reply);

    if (!ok) {
        cf_log(CF_LOG_ERROR, "dead-letter XADD failed", "origin_stream", origin_stream,
               "origin_id", origin_id, NULL);
        return -1;
    }

    CF_ATOMIC_INC(stats->deadletter_total);
    cf_log(CF_LOG_INFO, "dead_lettered", "reason", reason, "origin_stream", origin_stream,
           "origin_id", origin_id, NULL);
    return 0;
}
