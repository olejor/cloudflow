#ifndef CF_SINK_CLICKHOUSE_ROW_TRANSFORM_H
#define CF_SINK_CLICKHOUSE_ROW_TRANSFORM_H

/* WP-CH02 -- CloudFlowEvent -> one ClickHouse JSONEachRow row (the row
 * mapping / column contract).
 *
 * A cf_sink_transform_fn (libs/cloudflow-sink-core, cf_sink_consumer.h): for
 * one already-unpacked CloudFlowEvent it appends exactly ONE JSONEachRow object
 * (no trailing newline) to the spine's output buffer. The batched-INSERT client
 * concatenates the batch's rows with '\n', which is the JSONEachRow wire form,
 * and POSTs them to `INSERT INTO <db>.<table> FORMAT JSONEachRow`.
 *
 * One wide `events` table holds every event; protocol-specific columns are
 * simply OMITTED from the JSON for events of another protocol, so ClickHouse
 * fills their table DEFAULTs (schema/cloudflow_events.sql). The emitted keys are
 * a stable, documented contract:
 *
 *   common (every row):
 *     event_id           envelope.event_id (the ReplacingMergeTree dedup key)
 *     observed_time      envelope.observed_time_unix_nano as epoch seconds with
 *                        9 decimals -> a DateTime64(9) value
 *     source_type        "dhcpv4" | "dhcpv6" | "dns"
 *     source_host        envelope.source_host
 *     capture_interface  envelope.capture_interface
 *     event_type         envelope.event_type
 *     src_ip, dst_ip     PacketObservation.network src/dst (query_packet for DNS)
 *     src_mac            PacketObservation.link.src_mac
 *
 *   DHCP (dhcpv4 / dhcpv6 events):
 *     message_type       decoded/header message-type mnemonic
 *     client_key         normalized client key (client-id/chaddr; DUID hex for v6)
 *     requested_address  DHCPv4 option 50 requested IP, when present
 *     assigned_address   DHCPv4 lease_address / DHCPv6 first assigned addr, when present
 *     is_relayed         0/1
 *
 *   DNS (dns.transaction.observed and the query/response-only variants):
 *     qname, qtype, qclass   first question (qtype as mnemonic when known)
 *     rcode                  response rcode mnemonic, when a response is present
 *     rtt_seconds, rtt_valid rtt_nanos/1e9 and its validity flag (0/1)
 *     role                   leg role (client_facing / backend / recursion_upstream)
 *     service_role           operator-assigned tier, when non-empty
 *     client_ip, server_ip   normalized DNS identity (docs/event-model.md)
 *
 * Uses the normalized identity from docs/event-model.md (client key / client IP
 * / role), not the raw nested addresses, for the protocol columns. Returns 0 on
 * success; non-zero only for a genuinely unmappable event (missing envelope /
 * unset payload), which the spine dead-letters. `user` is unused (NULL). */

#include "cf_sink_consumer.h" /* cf_sink_buf_t */

#include "cloudflow/v1/envelope.pb-c.h"

int cf_row_transform(void *user, const Cloudflow__V1__CloudFlowEvent *ev,
                     const char *source_stream, cf_sink_buf_t *out);

#endif
