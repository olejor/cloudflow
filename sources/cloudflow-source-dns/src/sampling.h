#ifndef CF_DNS_SAMPLING_H
#define CF_DNS_SAMPLING_H

#include <stdint.h>

#include "correlation.h"   /* cf_dns_txn_outcome_t */

/* DNS sampling / emit-policy engine (WP-DNS10, docs/dns-source.md decision
 * DNS-D8 "Bounded everything, visible loss").
 *
 * DNS volume is far higher than DHCP, so the source ships a first-class
 * emit policy rather than emitting every correlated transaction. This module
 * is the pure decision: given the policy and a transaction's salient fields,
 * decide EMIT or SAMPLE-OUT (drop). It knows nothing about protobuf, queues
 * or the correlator's internals -- the caller (WP-DNS07) hands it the facts,
 * acts on the verdict, and owns the counters.
 *
 * DETERMINISM. There is NO RNG. Sampling keeps 1 of every N transactions by
 * mixing a stable per-transaction key (a hash of the correlation key material)
 * with splitmix64 and testing the mixed value modulo N. Replaying the same
 * capture therefore yields the same emit/drop decisions, and tests are stable.
 *
 * VISIBLE LOSS. A SAMPLE-OUT verdict (a 0 return in PREDICATE mode) is the
 * `dns_sampled_out_total` case from DNS-D8's counter list: the caller MUST
 * increment that named counter on every 0 return so the loss stays visible.
 * This module keeps no state and increments nothing itself.
 *
 * PURITY. C11, no allocation, no globals, no side effects; every function here
 * is a pure function of its arguments and is safe to call from any thread.
 */

/* Routine query types that PREDICATE mode is willing to sample. Everything
 * else (MX, TXT, SOA, SRV, ANY, unknown, ...) is always emitted. Values follow
 * the DNS qtype registry, mirrored by libs/cloudflow-codec's dns conventions. */
enum {
    CF_DNS_QTYPE_A    = 1,
    CF_DNS_QTYPE_AAAA = 28
};

/* The folded/extended rcode value that means "no error"; anything else is
 * always emitted in PREDICATE mode. */
enum {
    CF_DNS_RCODE_NOERROR = 0
};

typedef enum {
    CF_DNS_EMIT_ALL = 0,        /* default: emit every transaction */
    CF_DNS_EMIT_PREDICATE       /* predicate + sampling per DNS-D8 */
} cf_dns_emit_mode_t;

typedef struct {
    cf_dns_emit_mode_t mode;
    /* In PREDICATE mode, routine A/AAAA NOERROR OBSERVED transactions are
     * sampled: keep 1 of every `sample_denominator` (deterministically). 0 or
     * 1 means "keep all" (no sampling). */
    uint32_t sample_denominator;
} cf_dns_emit_policy_t;

/* Facts about the transaction the decision needs. */
typedef struct {
    cf_dns_txn_outcome_t outcome;
    uint32_t rcode;      /* folded/extended rcode from the response header */
    uint32_t qtype;
    int      has_response;   /* whether a response was seen (OBSERVED) */
    uint64_t sample_key;     /* stable per-transaction value (e.g. hash of the
                              * correlation key) for deterministic sampling */
} cf_dns_emit_facts_t;

/* Decide the fate of one transaction.
 *
 * Returns 1 to EMIT, 0 to SAMPLE-OUT (drop). ALL mode (and a NULL policy)
 * always returns 1. In PREDICATE mode a transaction is ALWAYS emitted if any
 * of these hold, checked in order:
 *   - outcome is UNANSWERED or UNMATCHED (the loss/anomaly signal -- never
 *     sampled),
 *   - rcode != NOERROR (0),
 *   - qtype is not a routine type (routine = A / AAAA).
 * Otherwise (a routine A/AAAA NOERROR OBSERVED transaction) it is sampled:
 * emitted iff sample_denominator <= 1 OR (splitmix64(sample_key) %
 * sample_denominator) == 0. A 0 return here is the `dns_sampled_out_total`
 * case -- the caller increments that counter. NULL facts return 0 (nothing to
 * emit) in PREDICATE mode. */
int cf_dns_emit_decide(const cf_dns_emit_policy_t *policy,
                       const cf_dns_emit_facts_t *f);

#endif /* CF_DNS_SAMPLING_H */
