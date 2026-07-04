#ifndef CF_SOURCE_DNS_DNS_STAGE_H
#define CF_SOURCE_DNS_DNS_STAGE_H

/* WP-DNS07 -- the DNS event stage: the pipeline thread that turns captured
 * frames into correlated, encoded CloudFlowEvents. It is the DNS analogue of
 * the DHCP source's event-formatter (sources/cloudflow-source-dhcp/src/
 * formatter.{c,h}), but with the one deliberately stateful stage of the
 * pipeline folded in -- the DNS-D5 correlation table -- so events are produced
 * not per input packet but per correlated *transaction* (DNS-D4).
 *
 * Per captured frame the stage (see docs/dns-source.md, DNS-D1/D6/D7/D9):
 *   1. decaps udp/53 or tcp/53 (cf_decap_udp, else cf_decap_tcp);
 *   2. for TCP strips the RFC 1035 2-byte length prefix, skipping (counting
 *      dns_tcp_partial_total) any multi-segment message it does not fully hold;
 *   3. parses the bare DNS message (cf_dns_parse);
 *   4. classifies the leg (cf_dns_classify_leg) -> role + local_is_server;
 *   5. builds the DNS-D6 correlation key (client = non-:53 endpoint, server =
 *      :53 endpoint) and, from the header QR bit, decides query vs response;
 *   6. builds a heap context owning the parsed DnsMessage, a PacketObservation,
 *      the raw frame bytes (for the DNS-D3 event_id) and the classified role;
 *   7. feeds the correlator (on_query / on_response), which hands each decided
 *      transaction back through the emit callback exactly once.
 *
 * The emit callback (the encode/enqueue point) applies the DNS-D8 sampling
 * policy, builds the EventEnvelope + DnsTransactionEvent (event_type one of
 * dns.transaction.observed / dns.query.unanswered / dns.response.unmatched),
 * enforces the D11 size cap (dropping raw_dns_payload before dropping the
 * event), packs it and pushes a cf_event_item_t to `out`. It closely mirrors
 * the DHCP formatter's envelope/event_id/encoding code.
 *
 * OWNERSHIP. The stage allocates one context per frame; the correlator hands
 * it back through exactly one emit() (as OBSERVED / UNANSWERED / UNMATCHED --
 * or, at teardown, UNANSWERED for every still-pending query). The context is
 * freed there, so there are no leaks across observed/unanswered/unmatched/
 * sampled-out (verified under ASan by tests/dns_stage_test.c).
 *
 * THREADING. Like the correlator (correlation.h), the stage is single-threaded
 * and owns its table exclusively -- parse and correlate share one thread, so
 * no locking is needed. The engine (dns_stage_t) is the reusable, thread-free
 * core used directly by tests; dns_stage_start()/dns_stage_stop() wrap it in
 * the pipeline thread, exactly as formatter_start()/formatter_stop() wrap
 * cf_format_packet().
 */

#include <stdint.h>

#include "cf_queue.h"
#include "cf_queue_policy.h"
#include "cloudflow.h"

#include "correlation.h"   /* cf_dns_correlator_config_t */
#include "leg_classify.h"  /* cf_dns_addr_set_t */
#include "sampling.h"      /* cf_dns_emit_policy_t */
#include "dns_source_stats.h"

typedef struct {
    /* Envelope provenance (config; borrowed -- must outlive the stage). */
    const char *source_host;         /* default gethostname() (app shell's job) */
    const char *source_instance;
    const char *capture_interface;
    const char *observation_method;  /* "rxring" or "pcap-replay" */

    /* Queues (both required for the threaded start()/stop(); process_packet()
     * uses only `out`). */
    cf_queue_t *in;                  /* of cf_packet_item_t */
    cf_queue_t *out;                 /* of cf_event_item_t; required */

    cf_dns_source_stats_t *stats;    /* required */
    cf_queue_full_policy_t on_full;  /* D9 policy for the push into `out` */

    /* Correlation table (DNS-D5/D8): capacity, timeout, table-full policy. */
    cf_dns_correlator_config_t correlator;

    /* Leg classifier (DNS-D7): the local-service and backend address sets,
     * each already built by the app shell (or NULL for "empty"). Borrowed. */
    const cf_dns_addr_set_t *local_addrs;
    const cf_dns_addr_set_t *backend_addrs;

    /* Service-role map (WP-DNS11a): server-side address -> operator label,
     * built by the app shell from dns.service_roles (or NULL for "none").
     * Borrowed. Sets the emitted DnsTransactionEvent.service_role; empty when
     * NULL, unmapped, or the server side is indeterminate. */
    const cf_dns_role_map_t *role_map;

    /* Sampling / emit policy (DNS-D8). */
    cf_dns_emit_policy_t emit_policy;
} dns_stage_config_t;

/* The thread-free engine: decap + parse + classify + correlate + sample +
 * encode over a caller-driven stream of frames. Opaque; owns a correlator. */
typedef struct dns_stage dns_stage_t;

/* Allocate an engine from `cfg` (copied by value; the string and queue/stats/
 * address-set pointers are borrowed and must outlive the engine). Returns NULL
 * on invalid config (NULL cfg/out/stats) or allocation failure. */
dns_stage_t *dns_stage_new(const dns_stage_config_t *cfg);

/* Free the engine. Drains every still-pending query as dns.query.unanswered
 * through the emit path first (so no context leaks), then frees the table.
 * NULL-safe. */
void dns_stage_free(dns_stage_t *stage);

/* Process one captured frame end to end (steps 1-7 above). Any transactions it
 * decides are emitted to cfg->out from within this call. Returns 0 if the frame
 * was decoded and fed to the correlator, 1 if it was skipped (non-DNS decap,
 * TCP partial, or unparseable -- counted, not an error), or -1 on a NULL
 * argument. */
int dns_stage_process_packet(dns_stage_t *stage, const cf_packet_item_t *pkt);

/* Run timeout eviction against `now_unix_nano`: every pending query older than
 * the configured timeout is emitted as dns.query.unanswered. Cheap; call
 * periodically so a quiet / one-sided table still drains. NULL-safe. */
void dns_stage_tick(dns_stage_t *stage, int64_t now_unix_nano);

/* Spawn the DNS event-stage thread: it pops cf_packet_item_t off cfg->in,
 * runs dns_stage_process_packet(), periodically ticks the correlator, and
 * pushes events to cfg->out. Returns 0 on success, -1 on error (bad config or
 * allocation/thread failure -- logged via cf_log). */
int dns_stage_start(const dns_stage_config_t *cfg);

/* Request shutdown, drain cfg->in (so nothing already queued is lost), free
 * the engine (which drains pending queries as unanswered), and join the
 * thread. Idempotent: safe when never started or already stopped. */
void dns_stage_stop(void);

#endif /* CF_SOURCE_DNS_DNS_STAGE_H */
