#include "sampling.h"

/* WP-DNS10 emit-policy decision. See sampling.h for the full contract; this
 * file is the pure, allocation-free, stateless implementation of DNS-D8's
 * "always emit anomalies, sample routine A/AAAA NOERROR" rule.
 */

/* splitmix64: a fast, well-distributed integer finalizer. Used to mix the
 * stable per-transaction sample_key so that `mixed % denominator == 0` selects
 * a uniform ~1/denominator share of keys, deterministically (no RNG). This is
 * the same avalanche mixer used by SplitMix64 / the finalizer in xoshiro seed
 * scrambling. */
static uint64_t cf_dns_splitmix64(uint64_t x)
{
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

/* A routine query type is one PREDICATE mode is willing to sample: A / AAAA.
 * Every other qtype (MX, TXT, SOA, SRV, ANY, unknown, ...) is always emitted. */
static int cf_dns_qtype_is_routine(uint32_t qtype)
{
    return qtype == CF_DNS_QTYPE_A || qtype == CF_DNS_QTYPE_AAAA;
}

int cf_dns_emit_decide(const cf_dns_emit_policy_t *policy,
                       const cf_dns_emit_facts_t *f)
{
    uint32_t denom;
    uint64_t mixed;

    /* ALL mode (and a missing policy) emits everything, unconditionally. */
    if (policy == NULL || policy->mode == CF_DNS_EMIT_ALL)
        return 1;

    /* PREDICATE mode with no facts: nothing to emit. */
    if (f == NULL)
        return 0;

    /* Anomaly/loss signals are never sampled -- always emitted. */
    if (f->outcome == CF_DNS_TXN_UNANSWERED ||
        f->outcome == CF_DNS_TXN_UNMATCHED)
        return 1;

    /* Any non-NOERROR response is always emitted. */
    if (f->rcode != CF_DNS_RCODE_NOERROR)
        return 1;

    /* Unusual (non-routine) query types are always emitted. */
    if (!cf_dns_qtype_is_routine(f->qtype))
        return 1;

    /* A routine A/AAAA NOERROR OBSERVED transaction: sample it. A denominator
     * of 0 or 1 means keep-all. Otherwise keep 1 of every `denom` keys by the
     * deterministic mix-and-modulo. */
    denom = policy->sample_denominator;
    if (denom <= 1)
        return 1;

    mixed = cf_dns_splitmix64(f->sample_key);
    return (mixed % denom) == 0 ? 1 : 0;
}
