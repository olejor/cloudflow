#ifndef CF_SINK_CORE_RUN_H
#define CF_SINK_CORE_RUN_H

/* Shared sink spine (A1) -- the consume -> transform -> batch -> deliver ->
 * ack run harness, extracted from the event sink's main() and parameterized by
 * a transform callback (cf_sink_transform_fn). Both the event sink and the
 * designed metrics sink drive their loop through this: parse config, fill a
 * cf_sink_run_options_t with the sink's transform, and call cf_sink_run.
 *
 * Preserves the --once / --stdout / SIGTERM-flush semantics: connects to the
 * first reachable Redis endpoint (D3), builds the HEC client (unless stdout
 * mode), installs the stop signal handlers, then runs once (drain-then-exit)
 * or forever (until SIGTERM flushes the in-flight batch once and exits). */

#include <stdio.h>

#include "cf_sink_config.h"
#include "cf_sink_consumer.h" /* cf_sink_transform_fn, cf_sink_buf_t */
#include "cf_sink_stats.h"

typedef struct {
    const cf_sink_config_t *config; /* base config (redis + hec topology) */
    cf_stats_t *stats;
    cf_sink_transform_fn transform; /* required */
    void *transform_user;           /* passed back to the transform */
    int stdout_mode;                /* print HEC lines instead of POSTing */
    int once;                       /* drain what is pending, then exit */
    long long min_idle_ms;          /* XAUTOCLAIM min-idle; <=0 => default 60s */
    FILE *stdout_stream;            /* stdout target in stdout mode; NULL => stdout */
} cf_sink_run_options_t;

/* Runs the sink loop. Returns 0 on a clean exit, non-zero on a fatal startup
 * failure (redis/HEC/consumer init). */
int cf_sink_run(const cf_sink_run_options_t *opt);

#endif
