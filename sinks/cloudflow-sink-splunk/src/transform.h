#ifndef CF_SINK_SPLUNK_TRANSFORM_H
#define CF_SINK_SPLUNK_TRANSFORM_H

/* WP-17 -- CloudFlowEvent -> Splunk HEC JSON (the canonical mapping).
 *
 * Reproduces, in C, exactly the JSON that the WP-12 Python transform produced
 * via google.protobuf.json_format.MessageToDict(preserving_proto_field_name=
 * True) wrapped in the HEC envelope (docs/design/04-sink-splunk.md,
 * "Canonical HEC mapping"; docs/design/06-sink-splunk-c.md, "Mapping
 * compatibility"):
 *
 *   - proto field names verbatim (snake_case);
 *   - proto3 defaults omitted (zero scalars, empty strings/bytes, unset
 *     messages, empty repeated); the set oneof member appears under its own
 *     field name;
 *   - enums as their .proto names; bytes as base64; 64-bit integers as JSON
 *     strings; 32-bit integers/bools/floats as JSON numbers/bools;
 *   - HEC envelope: time = observed_time_unix_nano/1e9 with exactly 9 decimal
 *     places, host/source/sourcetype/index per the mapping rules,
 *     raw_dhcp_payload stripped unless splunk.include_raw_payload.
 *
 * Output objects have their keys emitted in sorted order (like the Python
 * --stdout mode's json.dumps(sort_keys=True)) so diffs stay stable; the
 * golden compatibility test compares structurally regardless.
 */

#include "config.h"

#include "cloudflow/v1/envelope.pb-c.h"

/* Render one already-unpacked CloudFlowEvent as a single HEC JSON line (no
 * trailing newline). `stream_name` is the Redis stream the entry came from,
 * used as the `source` fallback when the envelope has no stream_name.
 * Returns a malloc'd NUL-terminated string the caller frees, or NULL on
 * error. */
char *cf_transform_render_hec_line(const Cloudflow__V1__CloudFlowEvent *ev,
                                   const char *stream_name,
                                   const cf_splunk_config_t *splunk);

#endif
