#include "consumer.h"

#include <stdlib.h>
#include <string.h>

#include "cf_log.h"
#include "cf_stats.h"
#include "cf_sync.h"
#include "cf_time.h"
#include "deadletter.h"
#include "transform.h"

#include "cloudflow/v1/envelope.pb-c.h"

#define REQUIRED_ENCODING "protobuf"
#define REQUIRED_SCHEMA "cloudflow.v1.CloudFlowEvent"

int cf_consumer_init(cf_consumer_t *c, redisContext *ctx, const cf_config_t *cfg,
                     cf_stats_t *stats)
{
    size_t i;

    memset(c, 0, sizeof(*c));
    c->ctx = ctx;
    c->cfg = cfg;
    c->stats = stats;
    c->stdout_stream = stdout;
    c->min_idle_ms = CF_CONSUMER_DEFAULT_MIN_IDLE_MS;
    c->last_flush_mono_ns = cf_now_mono_nano();

    c->autoclaim_cursors = calloc(cfg->redis.stream_count, sizeof(char *));
    if (!c->autoclaim_cursors)
        return -1;
    for (i = 0; i < cfg->redis.stream_count; i++) {
        c->autoclaim_cursors[i] = strdup("0-0");
        if (!c->autoclaim_cursors[i])
            return -1;
    }
    return 0;
}

void cf_consumer_set_stdout(cf_consumer_t *c, FILE *stream)
{
    c->stdout_mode = 1;
    c->stdout_stream = stream ? stream : stdout;
}

void cf_consumer_set_hec(cf_consumer_t *c, cf_hec_client_t *hec)
{
    c->stdout_mode = 0;
    c->hec = hec;
}

void cf_consumer_set_min_idle_ms(cf_consumer_t *c, long long ms)
{
    c->min_idle_ms = ms;
}

/* ---- batch buffer ------------------------------------------------------- */

static void batch_item_free(cf_consumer_batch_item_t *it)
{
    free(it->stream);
    free(it->entry_id);
    free(it->line);
    free(it->payload);
    memset(it, 0, sizeof(*it));
}

static void batch_clear(cf_consumer_t *c)
{
    size_t i;
    for (i = 0; i < c->batch_len; i++)
        batch_item_free(&c->batch[i]);
    c->batch_len = 0;
}

static int batch_append(cf_consumer_t *c, const char *stream, const char *entry_id, char *line,
                        const uint8_t *payload, size_t payload_len)
{
    cf_consumer_batch_item_t *it;

    if (c->batch_len == c->batch_cap) {
        size_t newcap = c->batch_cap ? c->batch_cap * 2 : 128;
        cf_consumer_batch_item_t *tmp = realloc(c->batch, newcap * sizeof(*tmp));
        if (!tmp)
            return -1;
        c->batch = tmp;
        c->batch_cap = newcap;
    }
    it = &c->batch[c->batch_len];
    memset(it, 0, sizeof(*it));
    it->stream = strdup(stream);
    it->entry_id = strdup(entry_id);
    it->line = line; /* takes ownership */
    it->payload = malloc(payload_len ? payload_len : 1);
    if (!it->stream || !it->entry_id || !it->payload) {
        batch_item_free(it);
        return -1;
    }
    if (payload_len)
        memcpy(it->payload, payload, payload_len);
    it->payload_len = payload_len;
    c->batch_len++;
    return 0;
}

/* ---- redis helpers ------------------------------------------------------ */

static void xack(cf_consumer_t *c, const char *stream, const char *entry_id)
{
    redisReply *r = redisCommand(c->ctx, "XACK %s %s %s", stream, c->cfg->redis.consumer_group,
                                 entry_id);
    if (r)
        freeReplyObject(r);
}

/* Find a field value (by key) in a redis "fields" reply (array k,v,k,v...).
 * Returns the value reply (binary via ->str/->len) or NULL. */
static const redisReply *field_get(const redisReply *fields, const char *key)
{
    size_t i;
    if (!fields || fields->type != REDIS_REPLY_ARRAY)
        return NULL;
    for (i = 0; i + 1 < fields->elements; i += 2) {
        const redisReply *k = fields->element[i];
        if (k && k->str && strcmp(k->str, key) == 0)
            return fields->element[i + 1];
    }
    return NULL;
}

static void dead_letter_and_ack(cf_consumer_t *c, const char *stream, const char *entry_id,
                                const char *reason, const char *error, const uint8_t *payload,
                                size_t payload_len)
{
    /* Dead-letter must succeed before ack; if it fails the entry stays
     * pending and is retried (at-least-once). */
    if (cf_deadletter_write(c->ctx, c->stats, reason, stream, entry_id, error, payload,
                            payload_len) == 0)
        xack(c, stream, entry_id);
}

static void process_entry(cf_consumer_t *c, const char *stream, const char *entry_id,
                          const redisReply *fields)
{
    const redisReply *encoding = field_get(fields, "encoding");
    const redisReply *schema = field_get(fields, "schema");
    const redisReply *payload = field_get(fields, "payload");
    const uint8_t *pbytes;
    size_t plen;
    Cloudflow__V1__CloudFlowEvent *ev;
    char *line;

    if (!encoding || !schema || !payload || encoding->type != REDIS_REPLY_STRING ||
        schema->type != REDIS_REPLY_STRING || payload->type != REDIS_REPLY_STRING ||
        strcmp(encoding->str, REQUIRED_ENCODING) != 0 ||
        strcmp(schema->str, REQUIRED_SCHEMA) != 0) {
        const uint8_t *pl = (payload && payload->str) ? (const uint8_t *)payload->str
                                                      : (const uint8_t *)"";
        size_t pll = (payload && payload->str) ? payload->len : 0;
        CF_ATOMIC_INC(c->stats->protobuf_decode_errors_total);
        dead_letter_and_ack(c, stream, entry_id, CF_DEADLETTER_REASON_DECODE_ERROR,
                            "invalid entry fields: encoding/schema mismatch", pl, pll);
        return;
    }

    pbytes = (const uint8_t *)payload->str;
    plen = payload->len;

    ev = cloudflow__v1__cloud_flow_event__unpack(NULL, plen, pbytes);
    if (!ev) {
        CF_ATOMIC_INC(c->stats->protobuf_decode_errors_total);
        dead_letter_and_ack(c, stream, entry_id, CF_DEADLETTER_REASON_DECODE_ERROR,
                            "protobuf parse error", pbytes, plen);
        return;
    }

    line = cf_transform_render_hec_line(ev, stream, &c->cfg->splunk);
    cloudflow__v1__cloud_flow_event__free_unpacked(ev, NULL);

    if (!line) {
        CF_ATOMIC_INC(c->stats->protobuf_decode_errors_total);
        dead_letter_and_ack(c, stream, entry_id, CF_DEADLETTER_REASON_DECODE_ERROR,
                            "transform error", pbytes, plen);
        return;
    }

    if (batch_append(c, stream, entry_id, line, pbytes, plen) != 0) {
        free(line);
        cf_log(CF_LOG_ERROR, "batch append failed (out of memory)", NULL);
    }
}

/* ---- flush -------------------------------------------------------------- */

static void flush_stdout(cf_consumer_t *c)
{
    size_t i;
    for (i = 0; i < c->batch_len; i++) {
        fprintf(c->stdout_stream, "%s\n", c->batch[i].line);
    }
    fflush(c->stdout_stream);
    CF_ATOMIC_ADD(c->stats->splunk_delivery_total, (unsigned long)c->batch_len);
    CF_ATOMIC_STORE(c->stats->splunk_batch_size_last, (unsigned long)c->batch_len);
    for (i = 0; i < c->batch_len; i++)
        xack(c, c->batch[i].stream, c->batch[i].entry_id);
}

static void flush_hec(cf_consumer_t *c)
{
    size_t n = c->batch_len, i;
    cf_batch_item_t *items;
    uint8_t *delivered, *poison;
    char **poison_errs;

    items = calloc(n, sizeof(*items));
    delivered = calloc(n, 1);
    poison = calloc(n, 1);
    poison_errs = calloc(n, sizeof(char *));
    if (!items || !delivered || !poison || !poison_errs) {
        cf_log(CF_LOG_ERROR, "flush allocation failed", NULL);
        free(items);
        free(delivered);
        free(poison);
        free(poison_errs);
        return;
    }

    for (i = 0; i < n; i++) {
        items[i].stream = c->batch[i].stream;
        items[i].entry_id = c->batch[i].entry_id;
        items[i].line = c->batch[i].line;
        items[i].payload = c->batch[i].payload;
        items[i].payload_len = c->batch[i].payload_len;
    }

    cf_hec_client_send_batch(c->hec, items, n, delivered, poison, poison_errs);

    for (i = 0; i < n; i++) {
        if (delivered[i]) {
            xack(c, c->batch[i].stream, c->batch[i].entry_id);
        } else if (poison[i]) {
            dead_letter_and_ack(c, c->batch[i].stream, c->batch[i].entry_id,
                                CF_DEADLETTER_REASON_HEC_REJECTED,
                                poison_errs[i] ? poison_errs[i] : "HEC rejected",
                                c->batch[i].payload, c->batch[i].payload_len);
        }
        /* Neither delivered nor poison should not happen (retryable retried
         * forever); leave unacked -> stays pending (at-least-once). */
        free(poison_errs[i]);
    }

    free(items);
    free(delivered);
    free(poison);
    free(poison_errs);
}

static void flush_batch(cf_consumer_t *c)
{
    c->last_flush_mono_ns = cf_now_mono_nano();
    if (c->batch_len == 0)
        return;
    if (c->stdout_mode)
        flush_stdout(c);
    else
        flush_hec(c);
    batch_clear(c);
}

static int should_flush(cf_consumer_t *c)
{
    if (c->batch_len == 0)
        return 0;
    if ((int)c->batch_len >= c->cfg->splunk.batch_size)
        return 1;
    if ((cf_now_mono_nano() - c->last_flush_mono_ns) / 1000000LL >=
        c->cfg->splunk.flush_interval_ms)
        return 1;
    return 0;
}

static void maybe_flush(cf_consumer_t *c)
{
    if (should_flush(c))
        flush_batch(c);
}

/* ---- reading ------------------------------------------------------------ */

int cf_consumer_ensure_groups(cf_consumer_t *c)
{
    size_t i;
    for (i = 0; i < c->cfg->redis.stream_count; i++) {
        redisReply *r = redisCommand(c->ctx, "XGROUP CREATE %s %s 0 MKSTREAM",
                                     c->cfg->redis.streams[i], c->cfg->redis.consumer_group);
        if (r && r->type == REDIS_REPLY_ERROR && !strstr(r->str, "BUSYGROUP")) {
            cf_log(CF_LOG_ERROR, "XGROUP CREATE failed", "stream", c->cfg->redis.streams[i],
                   "error", r->str, NULL);
            freeReplyObject(r);
            return -1;
        }
        if (r)
            freeReplyObject(r);
    }
    return 0;
}

/* Parse an entries array (as returned by XRANGE / XAUTOCLAIM / XREADGROUP):
 * each element is [id, [k,v,...]]. */
static void process_entries_array(cf_consumer_t *c, const char *stream, const redisReply *entries)
{
    size_t i;
    if (!entries || entries->type != REDIS_REPLY_ARRAY)
        return;
    for (i = 0; i < entries->elements; i++) {
        const redisReply *entry = entries->element[i];
        const redisReply *id;
        const redisReply *fields;
        if (!entry || entry->type != REDIS_REPLY_ARRAY || entry->elements < 2)
            continue;
        id = entry->element[0];
        fields = entry->element[1];
        if (!id || id->type != REDIS_REPLY_STRING)
            continue;
        process_entry(c, stream, id->str, fields);
    }
}

static void reclaim_stream(cf_consumer_t *c, size_t stream_idx)
{
    const char *stream = c->cfg->redis.streams[stream_idx];
    redisReply *r;
    const redisReply *cursor;
    const redisReply *entries;

    r = redisCommand(c->ctx, "XAUTOCLAIM %s %s %s %lld %s COUNT %d", stream,
                     c->cfg->redis.consumer_group, c->cfg->service.consumer_name, c->min_idle_ms,
                     c->autoclaim_cursors[stream_idx], c->cfg->redis.read_count);
    if (!r)
        return;
    if (r->type != REDIS_REPLY_ARRAY || r->elements < 2) {
        freeReplyObject(r);
        return;
    }
    cursor = r->element[0];
    entries = r->element[1];
    if (cursor && cursor->type == REDIS_REPLY_STRING) {
        free(c->autoclaim_cursors[stream_idx]);
        c->autoclaim_cursors[stream_idx] = strdup(cursor->str);
    }
    process_entries_array(c, stream, entries);
    freeReplyObject(r);
}

static void reclaim_all(cf_consumer_t *c)
{
    size_t i;
    for (i = 0; i < c->cfg->redis.stream_count; i++)
        reclaim_stream(c, i);
}

/* XREADGROUP GROUP g cons COUNT n [BLOCK ms] STREAMS s1..sn > .. > .
 * Returns number of entries processed. block_ms < 0 => no BLOCK. */
static int read_new(cf_consumer_t *c, long block_ms)
{
    size_t nstreams = c->cfg->redis.stream_count;
    size_t argc = 0, i;
    const char **argv;
    redisReply *r;
    char countbuf[16], blockbuf[24];
    int processed = 0;

    /* max args: XREADGROUP GROUP g c COUNT n BLOCK ms STREAMS + n streams + n ">" */
    argv = calloc(9 + nstreams * 2, sizeof(char *));
    if (!argv)
        return 0;

    snprintf(countbuf, sizeof(countbuf), "%d", c->cfg->redis.read_count);

    argv[argc++] = "XREADGROUP";
    argv[argc++] = "GROUP";
    argv[argc++] = c->cfg->redis.consumer_group;
    argv[argc++] = c->cfg->service.consumer_name;
    argv[argc++] = "COUNT";
    argv[argc++] = countbuf;
    if (block_ms >= 0) {
        snprintf(blockbuf, sizeof(blockbuf), "%ld", block_ms);
        argv[argc++] = "BLOCK";
        argv[argc++] = blockbuf;
    }
    argv[argc++] = "STREAMS";
    for (i = 0; i < nstreams; i++)
        argv[argc++] = c->cfg->redis.streams[i];
    for (i = 0; i < nstreams; i++)
        argv[argc++] = ">";

    r = redisCommandArgv(c->ctx, (int)argc, argv, NULL);
    free(argv);

    if (!r)
        return 0;
    if (r->type == REDIS_REPLY_ARRAY) {
        for (i = 0; i < r->elements; i++) {
            const redisReply *sr = r->element[i];
            const redisReply *sname, *entries;
            if (!sr || sr->type != REDIS_REPLY_ARRAY || sr->elements < 2)
                continue;
            sname = sr->element[0];
            entries = sr->element[1];
            if (!sname || sname->type != REDIS_REPLY_STRING)
                continue;
            if (entries && entries->type == REDIS_REPLY_ARRAY)
                processed += (int)entries->elements;
            process_entries_array(c, sname->str, entries);
        }
    }
    freeReplyObject(r);
    return processed;
}

int cf_consumer_run_once(cf_consumer_t *c)
{
    if (cf_consumer_ensure_groups(c) != 0)
        return -1;
    reclaim_all(c);
    maybe_flush(c);
    for (;;) {
        int n = read_new(c, -1); /* non-blocking */
        maybe_flush(c);
        if (n == 0)
            break;
    }
    flush_batch(c);
    return 0;
}

int cf_consumer_run_forever(cf_consumer_t *c)
{
    if (cf_consumer_ensure_groups(c) != 0)
        return -1;
    while (!cf_stop_notified()) {
        reclaim_all(c);
        maybe_flush(c);
        if (cf_stop_notified())
            break;
        read_new(c, c->cfg->redis.block_ms);
        maybe_flush(c);
        cf_stats_maybe_emit(c->stats, 10000);
    }
    /* Shutdown: flush the in-flight batch once, ack what succeeded, exit. */
    flush_batch(c);
    cf_stats_emit(c->stats);
    return 0;
}

void cf_consumer_free(cf_consumer_t *c)
{
    size_t i;
    if (!c)
        return;
    batch_clear(c);
    free(c->batch);
    c->batch = NULL;
    c->batch_cap = 0;
    if (c->autoclaim_cursors) {
        for (i = 0; i < c->cfg->redis.stream_count; i++)
            free(c->autoclaim_cursors[i]);
        free(c->autoclaim_cursors);
        c->autoclaim_cursors = NULL;
    }
}
