#ifndef CF_SINK_SPLUNK_METRICS_TRANSFORM_H
#define CF_SINK_SPLUNK_METRICS_TRANSFORM_H

/* WP-M02 -- CloudFlowEvent -> Splunk metric-point JSON (the metric mapping).
 *
 * A cf_sink_transform_fn (libs/cloudflow-sink-core, cf_sink_consumer.h): for
 * one already-unpacked CloudFlowEvent it appends zero or more Splunk
 * metric-point objects (docs/splunk-metrics.md, "Metric-point format") to the
 * spine's output buffer, newline-delimited, no trailing newline. Each point is:
 *
 *   { "time": <observed wire time, 9 decimals>,
 *     "source": <stream>, "sourcetype": "cloudflow:metric",
 *     "host": <envelope.source_host>, "index": <splunk.metrics_index>,
 *     "fields": { "metric_name:<name>": <value>, <dimension keys...> } }
 *
 * Metrics (docs/splunk-metrics.md, "Metric mapping"):
 *   DNS dns.transaction.observed -> dns.transactions_total(=1) and, when
 *     rtt_valid, dns.rtt_seconds(=rtt_nanos/1e9), dimensioned by cf_role,
 *     cf_service_role (omitted if empty), cf_rcode, cf_qtype, cf_server_ip;
 *   DNS dns.query.unanswered      -> dns.unanswered_total(=1) by cf_role/cf_service_role;
 *   DNS dns.response.unmatched    -> dns.unmatched_total(=1)  by cf_role/cf_service_role;
 *   DHCP any packet event         -> dhcp.events_total(=1) by source_type,
 *     cf_message_type, cf_is_relayed (per-client key is opt-in via config).
 *
 * The `enabled_metrics` allowlist and the `dimensions` cardinality controls in
 * the config gate which metrics and which optional dimensions are emitted. An
 * event that maps to no (enabled) metric is a valid success with no output.
 *
 * Returns 0 on success (including "no output"); non-zero only for a genuinely
 * unmappable event (missing envelope / unset payload), which the spine
 * dead-letters. `user` is a const cf_config_t *. */

#include "config.h"

#include "cf_sink_consumer.h" /* cf_sink_buf_t */

#include "cloudflow/v1/envelope.pb-c.h"

int cf_metrics_transform(void *user, const Cloudflow__V1__CloudFlowEvent *ev,
                         const char *source_stream, cf_sink_buf_t *out);

#endif
