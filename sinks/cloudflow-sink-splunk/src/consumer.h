#ifndef CF_SINK_SPLUNK_CONSUMER_H
#define CF_SINK_SPLUNK_CONSUMER_H

/* WP-17 -- Redis consumer-group logic (hiredis).
 *
 * docs/splunk-output.md, "Consumer behavior":
 *  - XGROUP CREATE <stream> <group> 0 MKSTREAM per stream (BUSYGROUP ignored);
 *  - reclaim stale pending entries first (XAUTOCLAIM min-idle 60s), then
 *    XREADGROUP COUNT read_count [BLOCK block_ms] ... > ;
 *  - validate each entry's encoding/schema fields, protobuf-unpack the
 *    payload; any decode failure is dead-lettered (reason=decode_error) then
 *    XACKed;
 *  - transformed events are batched; entries are XACKed only after their
 *    batch got a 2xx (or after confirmed dead-lettering, reason=hec_rejected);
 *  - SIGTERM (via cf_stop_notified): flush the in-flight batch once, ack what
 *    succeeded, exit. */

#include <stdint.h>
#include <stdio.h>

#include <hiredis/hiredis.h>

#include "config.h"
#include "hec.h"
#include "stats.h"

#define CF_CONSUMER_DEFAULT_MIN_IDLE_MS 60000

typedef struct {
    char *stream;
    char *entry_id;
    char *line;
    uint8_t *payload;
    size_t payload_len;
} cf_consumer_batch_item_t;

typedef struct {
    redisContext *ctx;
    const cf_config_t *cfg;
    cf_stats_t *stats;

    int stdout_mode;       /* 1 = print lines; 0 = POST via `hec` */
    FILE *stdout_stream;   /* used in stdout mode; default stdout */
    cf_hec_client_t *hec;  /* used in POST mode */

    long long min_idle_ms; /* XAUTOCLAIM min-idle; default 60000 */

    cf_consumer_batch_item_t *batch;
    size_t batch_len;
    size_t batch_cap;
    int64_t last_flush_mono_ns;

    char **autoclaim_cursors; /* one per configured stream */
} cf_consumer_t;

/* Initialize against an established redis context. Defaults: stdout mode off,
 * stdout stream = stdout, min_idle 60s. Returns 0 on success. */
int cf_consumer_init(cf_consumer_t *c, redisContext *ctx, const cf_config_t *cfg,
                     cf_stats_t *stats);

void cf_consumer_set_stdout(cf_consumer_t *c, FILE *stream);
void cf_consumer_set_hec(cf_consumer_t *c, cf_hec_client_t *hec);
void cf_consumer_set_min_idle_ms(cf_consumer_t *c, long long ms);

int cf_consumer_ensure_groups(cf_consumer_t *c);
int cf_consumer_run_once(cf_consumer_t *c);
int cf_consumer_run_forever(cf_consumer_t *c);

void cf_consumer_free(cf_consumer_t *c);

#endif
