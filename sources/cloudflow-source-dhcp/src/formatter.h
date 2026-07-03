#ifndef CF_SOURCE_DHCP_FORMATTER_H
#define CF_SOURCE_DHCP_FORMATTER_H

/* WP-10: the event-formatter thread. Pops cf_packet_item_t off `in`, decaps
 * (libs/cloudflow-packet's cf_decap_udp, WP-05), parses DHCPv4/DHCPv6
 * (cf_dhcpv4_parse/cf_dhcpv6_parse, WP-06/07), builds the CloudFlowEvent
 * envelope (proto/cloudflow/v1/envelope.proto + common.proto), packs it with
 * protobuf-c into a cf_event_item_t, and pushes it to `out`. Per D10
 * (docs/architecture.md), this is the only place in the source that
 * parses DHCP or allocates -- the rx-reader thread (WP-08) does neither.
 *
 * See docs/dhcp-source.md's WP-10 section for the authoritative
 * spec this implements. */

#include <stdint.h>

#include "cf_queue.h"
#include "cloudflow.h"
#include "queue_policy.h"
#include "source_stats.h"

/* Returned by cf_format_packet() for a packet that decap/classification
 * could not attribute to DHCPv4/DHCPv6, that the relevant parser could not
 * even build a tree for, or whose packed event still exceeded
 * CLOUDFLOW_EVENT_MAX_SIZE after the D11 raw-payload-drop retry -- in every
 * case the packet is counted (via the appropriate cf_source_stats_t field)
 * and not pushed, but this is not treated as an error by the caller. */
#define CF_FORMAT_SKIP 1

typedef struct {
    const char *source_host;         /* config; default gethostname() (WP-11's job) */
    const char *source_instance;
    const char *capture_interface;
    const char *observation_method;  /* "rxring" or "pcap-replay" */
    cf_queue_t *in;                  /* of cf_packet_item_t; required */
    cf_queue_t *out;                 /* of cf_event_item_t; required */
    cf_source_stats_t *stats;        /* required */
    cf_queue_full_policy_t on_full;
} formatter_config_t;

/* Pure function: decap + classify + parse + build envelope + pack. No
 * threads, no queues -- used directly by formatter_start()'s thread loop and
 * by tests. Returns 0 on success (`item` is fully populated), CF_FORMAT_SKIP
 * for a non-DHCP/undecodable/oversize-dropped packet (counted, not an
 * error), or a negative value on a real error (e.g. allocation failure --
 * `item` is left untouched). */
int cf_format_packet(const formatter_config_t *cfg, const cf_packet_item_t *pkt,
                      cf_event_item_t *item);

/* Spawns the formatter thread. Returns 0 on success, -1 on error (bad
 * config -- logged via cf_log). */
int formatter_start(const formatter_config_t *cfg);

/* Requests shutdown (if not already notified), drains `cfg->in` (so a
 * formatter stopped after its upstream rx-reader/pcap-replay has already
 * stopped loses nothing still sitting in the queue), and joins the thread.
 * Idempotent: safe to call when never started or already stopped. */
void formatter_stop(void);

#endif
