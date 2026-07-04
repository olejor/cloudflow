#ifndef CF_DNS_CORRELATION_H
#define CF_DNS_CORRELATION_H

#include <stddef.h>
#include <stdint.h>

/* DNS query/response correlation stage (WP-DNS04, docs/dns-source.md
 * "Correlation stage (the pending table)", decisions DNS-D5/D6/D8/D9).
 *
 * A bounded, PRE-ALLOCATED pending-query table that matches DNS queries to
 * their responses, computes RTT, and evicts on timeout. It is the one
 * deliberately stateful stage of the otherwise stateless-observer pipeline
 * (DNS-D5): capture-time correlation is the only way to get honest sub-
 * millisecond RTT, and correlating downstream in Splunk is lossy at query
 * volume.
 *
 * Design goals, straight from AGENTS.md and DNS-D8:
 *   - bounded everything: a fixed-capacity table sized at construction
 *     (capacity * sizeof(entry)), no per-operation heap churn in steady
 *     state -- only cf_dns_correlator_new()/_free() allocate;
 *   - visible loss: every eviction, collision, table-full drop and invalid
 *     RTT is a named counter surfaced through cf_dns_correlator_stats();
 *   - no hidden buffering: a query is either matched, evicted (timeout /
 *     collision / table-full) or drained at teardown -- it is always handed
 *     back to the caller exactly once.
 *
 * THREADING. This module is single-threaded and owns its table exclusively;
 * it takes no locks. In the DNS source the pipeline is
 *   rx-reader -> [pkt queue] -> parse + correlate -> [event queue] -> redis
 * so parse and correlate share one thread and the table needs no
 * synchronization. Do not call any cf_dns_correlator_* function for the same
 * correlator from two threads.
 *
 * DECOUPLING FROM PROTOBUF. The correlator knows nothing about
 * DnsTransactionEvent / envelope assembly. The caller (WP-DNS07) supplies an
 * emit callback and an opaque per-query "context" pointer; when a query's
 * fate is decided the correlator invokes emit with that context and the
 * matched outcome, and the caller does the encode/enqueue there. This keeps
 * the table unit-testable with hand-built keys and fake contexts, no packet
 * parsing required.
 *
 * OWNERSHIP CONTRACT (verified under ASan by tests/correlation_test.c):
 *   - cf_dns_correlator_on_query() TAKES OWNERSHIP of query_ctx. That context
 *     is handed back through EXACTLY ONE emit() call -- as OBSERVED (matched),
 *     or UNANSWERED (timeout eviction, same-key collision eviction, table-full
 *     drop, or the free-time drain). It is never dropped silently and never
 *     handed back twice.
 *   - cf_dns_correlator_on_response() does NOT retain response_ctx: it is
 *     passed straight through to exactly one emit() call (OBSERVED on a match,
 *     UNMATCHED on a miss) and never stored.
 *   - cf_dns_correlator_free() drains every still-pending query as UNANSWERED
 *     so no query context can leak.
 * The caller frees its context(s) inside the emit callback. The correlator
 * never frees a context itself.
 */

/* The DNS-D6 correlation key, canonicalized by the caller so that a query and
 * its response map to the SAME key: `client` is the non-:53 endpoint,
 * `server` is the :53 endpoint. The correlator hashes/compares this struct
 * verbatim (endpoints are NOT swapped internally); WP-DNS05's leg classifier
 * is responsible for producing identical keys for both halves. */
typedef struct {
    uint8_t  transport;        /* 0 = udp, 1 = tcp */
    uint8_t  local_is_server;  /* from the leg classifier (WP-DNS05) */
    uint8_t  ip_version;       /* 4 or 6 */
    uint8_t  client_ip[16], server_ip[16];  /* network order; v4 in first 4 */
    uint16_t client_port, server_port;      /* server_port is normally 53 */
    uint16_t dns_id;
    uint16_t qtype, qclass;
    /* 0x20-normalized (lowercased) qname, kept as a bounded literal copy so a
     * query and its response with different DNS-0x20 casing still collide on
     * one key. It participates in the key; only the first qname_len bytes are
     * significant. */
    uint8_t  qname_canonical[256];
    uint16_t qname_len;        /* <= sizeof(qname_canonical) */
} cf_dns_txn_key_t;

typedef enum {
    CF_DNS_TXN_OBSERVED,    /* query matched to its response */
    CF_DNS_TXN_UNANSWERED,  /* pending query evicted (timeout/collision/full/drain) */
    CF_DNS_TXN_UNMATCHED    /* response with no pending query */
} cf_dns_txn_outcome_t;

/* Emit callback. Exactly one of the three outcomes per call:
 *   OBSERVED   -> query_ctx AND response_ctx both set; rtt_nanos is the
 *                 response-minus-query delta and rtt_valid says whether it is
 *                 plausible (DNS-D9).
 *   UNANSWERED -> query_ctx set, response_ctx NULL; rtt_* are 0/0.
 *   UNMATCHED  -> query_ctx NULL, response_ctx set; rtt_* are 0/0.
 * `key` is the correlation key involved (never NULL) and is only valid for
 * the duration of the call. `user` is the pointer passed to _new(). */
typedef void (*cf_dns_emit_fn)(void *user, cf_dns_txn_outcome_t outcome,
                               void *query_ctx, void *response_ctx,
                               int64_t rtt_nanos, int rtt_valid,
                               const cf_dns_txn_key_t *key);

/* Table-full policy, mirroring the D9 queue backpressure discipline. */
enum {
    CF_DNS_ON_FULL_DROP_NEWEST = 0, /* default: drop the just-arrived query */
    CF_DNS_ON_FULL_DROP_OLDEST = 1  /* evict the oldest pending to make room */
};

typedef struct {
    size_t   capacity;              /* pending table size, pre-allocated (>= 1) */
    int64_t  query_timeout_nanos;   /* evict older-than as UNANSWERED (> 0) */
    int      on_table_full;         /* CF_DNS_ON_FULL_DROP_NEWEST (default) / _OLDEST */
} cf_dns_correlator_config_t;

typedef struct {
    uint64_t transactions_observed;      /* query matched to response */
    uint64_t query_unanswered;           /* timeout + free-drain evictions */
    uint64_t response_unmatched;         /* responses with no pending query */
    uint64_t pending_evicted_collision;  /* same-key retransmit/port-reuse evictions */
    uint64_t pending_drop;               /* table-full drops (either policy) */
    uint64_t rtt_invalid;                /* matched but RTT negative / implausible */
    size_t   pending_depth;              /* current pending-table gauge */
} cf_dns_correlator_stats_t;

typedef struct cf_dns_correlator cf_dns_correlator_t;

/* Allocate a correlator with a pre-allocated table of cfg->capacity entries.
 * Returns NULL on invalid arguments (NULL cfg/emit, capacity 0, or
 * query_timeout_nanos <= 0) or allocation failure. */
cf_dns_correlator_t *cf_dns_correlator_new(const cf_dns_correlator_config_t *cfg,
                                           cf_dns_emit_fn emit, void *user);

/* Drain every still-pending query as UNANSWERED (so no context leaks), then
 * free the table. NULL-safe. */
void cf_dns_correlator_free(cf_dns_correlator_t *c);

/* Insert a parsed query. Takes ownership of query_ctx (see the ownership
 * contract above). observed_time_unix_nano is capture time (DNS-D9). */
void cf_dns_correlator_on_query(cf_dns_correlator_t *c, const cf_dns_txn_key_t *key,
                                int64_t observed_time_unix_nano, void *query_ctx);

/* Match a parsed response against the pending table. Does not retain
 * response_ctx. */
void cf_dns_correlator_on_response(cf_dns_correlator_t *c, const cf_dns_txn_key_t *key,
                                   int64_t observed_time_unix_nano, void *response_ctx);

/* Evict every entry older than query_timeout_nanos relative to now as
 * UNANSWERED. Cheap to call periodically so a quiet table still drains. */
void cf_dns_correlator_tick(cf_dns_correlator_t *c, int64_t now_unix_nano);

/* Snapshot the counters (and the pending-depth gauge). NULL-safe on out. */
void cf_dns_correlator_stats(const cf_dns_correlator_t *c,
                             cf_dns_correlator_stats_t *out);

#endif /* CF_DNS_CORRELATION_H */
