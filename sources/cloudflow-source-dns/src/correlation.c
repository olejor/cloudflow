#include "correlation.h"

#include <stdlib.h>
#include <string.h>

/* Bounded pending-query table (WP-DNS04). See correlation.h for the full
 * contract; this file is the single-threaded, pre-allocated implementation.
 *
 * Structure. A fixed pool of `capacity` entries, allocated once. The entries
 * are indexed three ways, all through stable int32 indices into the pool (an
 * entry never moves, so every index stays valid for its lifetime):
 *
 *   1. A hash table over the DNS-D6 key using SEPARATE CHAINING -- `buckets`
 *      holds a per-bucket head index and each entry chains via `hnext`.
 *      Separate chaining (rather than open-addressing with tombstones) means
 *      lookups stay short as the table churns and no compaction/backward-shift
 *      is ever needed, so entries can keep stable indices.
 *   2. A doubly-linked FIFO list in insertion order (`fifo_prev`/`fifo_next`,
 *      `head`/`tail`) -- the time-ordered index for timeout and drop-oldest
 *      eviction. Capture time is non-decreasing across on_query() in the
 *      pipeline, so the FIFO head is the oldest pending query; eviction walks
 *      from the head and stops at the first non-expired entry.
 *   3. A singly-linked free list (reusing `hnext` while an entry is free) so
 *      allocating/releasing a slot is O(1) with no heap traffic.
 *
 * Memory is buckets[nbuckets] + entries[capacity], both allocated in _new().
 */

#define CF_DNS_NIL (-1)

/* Bound on eviction work amortized onto each on_query() so a busy table
 * drains without waiting for a tick (docs/dns-source.md: "Eviction runs
 * amortized on each insert and on a periodic tick"). */
#define CF_DNS_AMORTIZED_EVICT_MAX 8

typedef struct {
    cf_dns_txn_key_t key;
    int64_t          observed_time;
    void            *query_ctx;
    int32_t          hnext;      /* next in bucket chain, or next free slot */
    int32_t          fifo_prev;  /* FIFO (time-order) links */
    int32_t          fifo_next;
} cf_dns_entry_t;

struct cf_dns_correlator {
    cf_dns_entry_t *entries;
    int32_t        *buckets;
    size_t          capacity;
    size_t          nbuckets;   /* power of two >= capacity */
    uint32_t        bucket_mask;

    int32_t         free_head;
    int32_t         fifo_head;  /* oldest */
    int32_t         fifo_tail;  /* newest */
    size_t          count;

    int64_t         query_timeout_nanos;
    int             on_table_full;

    cf_dns_emit_fn  emit;
    void           *user;

    cf_dns_correlator_stats_t stats;
};

/* ---- key hashing / comparison -------------------------------------------- */

/* Number of significant qname bytes (defensively clamped to the buffer). */
static size_t key_qname_len(const cf_dns_txn_key_t *k)
{
    size_t n = k->qname_len;

    if (n > sizeof(k->qname_canonical))
        n = sizeof(k->qname_canonical);
    return n;
}

/* FNV-1a over exactly the fields that make up the DNS-D6 key. */
static uint64_t key_hash(const cf_dns_txn_key_t *k)
{
    uint64_t h = 1469598103934665603ULL; /* FNV offset basis */
    size_t   qn = key_qname_len(k);
    size_t   i;

#define CF_DNS_FNV_BYTE(b)                                                     \
    do {                                                                       \
        h ^= (uint64_t)(uint8_t)(b);                                           \
        h *= 1099511628211ULL;                                                 \
    } while (0)

    CF_DNS_FNV_BYTE(k->transport);
    CF_DNS_FNV_BYTE(k->local_is_server);
    CF_DNS_FNV_BYTE(k->ip_version);
    for (i = 0; i < sizeof(k->client_ip); i++)
        CF_DNS_FNV_BYTE(k->client_ip[i]);
    for (i = 0; i < sizeof(k->server_ip); i++)
        CF_DNS_FNV_BYTE(k->server_ip[i]);
    CF_DNS_FNV_BYTE(k->client_port & 0xff);
    CF_DNS_FNV_BYTE(k->client_port >> 8);
    CF_DNS_FNV_BYTE(k->server_port & 0xff);
    CF_DNS_FNV_BYTE(k->server_port >> 8);
    CF_DNS_FNV_BYTE(k->dns_id & 0xff);
    CF_DNS_FNV_BYTE(k->dns_id >> 8);
    CF_DNS_FNV_BYTE(k->qtype & 0xff);
    CF_DNS_FNV_BYTE(k->qtype >> 8);
    CF_DNS_FNV_BYTE(k->qclass & 0xff);
    CF_DNS_FNV_BYTE(k->qclass >> 8);
    for (i = 0; i < qn; i++)
        CF_DNS_FNV_BYTE(k->qname_canonical[i]);
    CF_DNS_FNV_BYTE(qn & 0xff);
    CF_DNS_FNV_BYTE((qn >> 8) & 0xff);

#undef CF_DNS_FNV_BYTE
    return h;
}

static int key_equal(const cf_dns_txn_key_t *a, const cf_dns_txn_key_t *b)
{
    size_t qa = key_qname_len(a);
    size_t qb = key_qname_len(b);

    if (a->transport != b->transport || a->local_is_server != b->local_is_server ||
        a->ip_version != b->ip_version || a->client_port != b->client_port ||
        a->server_port != b->server_port || a->dns_id != b->dns_id ||
        a->qtype != b->qtype || a->qclass != b->qclass || qa != qb)
        return 0;
    if (memcmp(a->client_ip, b->client_ip, sizeof(a->client_ip)) != 0)
        return 0;
    if (memcmp(a->server_ip, b->server_ip, sizeof(a->server_ip)) != 0)
        return 0;
    if (memcmp(a->qname_canonical, b->qname_canonical, qa) != 0)
        return 0;
    return 1;
}

/* ---- intrusive list plumbing --------------------------------------------- */

static uint32_t bucket_of(const cf_dns_correlator_t *c, uint64_t h)
{
    return (uint32_t)(h & c->bucket_mask);
}

static void fifo_append(cf_dns_correlator_t *c, int32_t idx)
{
    cf_dns_entry_t *e = &c->entries[idx];

    e->fifo_next = CF_DNS_NIL;
    e->fifo_prev = c->fifo_tail;
    if (c->fifo_tail != CF_DNS_NIL)
        c->entries[c->fifo_tail].fifo_next = idx;
    else
        c->fifo_head = idx;
    c->fifo_tail = idx;
}

static void fifo_unlink(cf_dns_correlator_t *c, int32_t idx)
{
    cf_dns_entry_t *e = &c->entries[idx];

    if (e->fifo_prev != CF_DNS_NIL)
        c->entries[e->fifo_prev].fifo_next = e->fifo_next;
    else
        c->fifo_head = e->fifo_next;
    if (e->fifo_next != CF_DNS_NIL)
        c->entries[e->fifo_next].fifo_prev = e->fifo_prev;
    else
        c->fifo_tail = e->fifo_prev;
}

/* Detach an in-use entry from the bucket chain and FIFO, return it to the
 * free list. Does not touch the caller's context. */
static void entry_release(cf_dns_correlator_t *c, int32_t idx)
{
    uint32_t b = bucket_of(c, key_hash(&c->entries[idx].key));
    int32_t  cur = c->buckets[b];
    int32_t  prev = CF_DNS_NIL;

    while (cur != CF_DNS_NIL && cur != idx) {
        prev = cur;
        cur = c->entries[cur].hnext;
    }
    if (cur == idx) {
        if (prev == CF_DNS_NIL)
            c->buckets[b] = c->entries[idx].hnext;
        else
            c->entries[prev].hnext = c->entries[idx].hnext;
    }

    fifo_unlink(c, idx);

    c->entries[idx].hnext = c->free_head;
    c->free_head = idx;
    c->count--;
}

/* Look up a key; returns the entry index or CF_DNS_NIL. */
static int32_t entry_find(const cf_dns_correlator_t *c, const cf_dns_txn_key_t *key,
                          uint64_t h)
{
    int32_t idx = c->buckets[bucket_of(c, h)];

    while (idx != CF_DNS_NIL) {
        if (key_equal(&c->entries[idx].key, key))
            return idx;
        idx = c->entries[idx].hnext;
    }
    return CF_DNS_NIL;
}

/* Hand a pending query's context back to the caller as UNANSWERED and free
 * its slot. `counter` is the stat to bump for this eviction class. */
static void evict_as_unanswered(cf_dns_correlator_t *c, int32_t idx, uint64_t *counter)
{
    void            *ctx = c->entries[idx].query_ctx;
    cf_dns_txn_key_t key = c->entries[idx].key;

    entry_release(c, idx);
    (*counter)++;
    c->emit(c->user, CF_DNS_TXN_UNANSWERED, ctx, NULL, 0, 0, &key);
}

/* Evict up to `budget` expired entries from the FIFO head. Returns the number
 * evicted. Relies on capture time being non-decreasing across inserts, so the
 * first non-expired head means the rest are younger still. */
static size_t evict_expired(cf_dns_correlator_t *c, int64_t now, size_t budget)
{
    size_t n = 0;

    while (n < budget && c->fifo_head != CF_DNS_NIL) {
        int32_t idx = c->fifo_head;

        if (now - c->entries[idx].observed_time <= c->query_timeout_nanos)
            break;
        evict_as_unanswered(c, idx, &c->stats.query_unanswered);
        n++;
    }
    return n;
}

/* ---- public API ---------------------------------------------------------- */

static size_t next_pow2(size_t n)
{
    size_t p = 1;

    while (p < n)
        p <<= 1;
    return p;
}

cf_dns_correlator_t *cf_dns_correlator_new(const cf_dns_correlator_config_t *cfg,
                                           cf_dns_emit_fn emit, void *user)
{
    cf_dns_correlator_t *c;
    size_t               i;

    if (!cfg || !emit || cfg->capacity == 0 || cfg->query_timeout_nanos <= 0)
        return NULL;
    /* Keep every index representable as int32 with room for the NIL sentinel. */
    if (cfg->capacity > (size_t)INT32_MAX)
        return NULL;

    c = calloc(1, sizeof(*c));
    if (!c)
        return NULL;

    c->capacity = cfg->capacity;
    c->nbuckets = next_pow2(cfg->capacity);
    c->bucket_mask = (uint32_t)(c->nbuckets - 1);
    c->query_timeout_nanos = cfg->query_timeout_nanos;
    c->on_table_full = cfg->on_table_full;
    c->emit = emit;
    c->user = user;
    c->free_head = 0;
    c->fifo_head = CF_DNS_NIL;
    c->fifo_tail = CF_DNS_NIL;

    c->entries = malloc(c->capacity * sizeof(*c->entries));
    c->buckets = malloc(c->nbuckets * sizeof(*c->buckets));
    if (!c->entries || !c->buckets) {
        free(c->entries);
        free(c->buckets);
        free(c);
        return NULL;
    }

    for (i = 0; i < c->nbuckets; i++)
        c->buckets[i] = CF_DNS_NIL;
    /* Thread all slots onto the free list via hnext. */
    for (i = 0; i < c->capacity; i++)
        c->entries[i].hnext = (i + 1 < c->capacity) ? (int32_t)(i + 1) : CF_DNS_NIL;

    return c;
}

void cf_dns_correlator_free(cf_dns_correlator_t *c)
{
    if (!c)
        return;

    /* Drain: hand every still-pending query back as UNANSWERED so no context
     * leaks (ownership contract). */
    while (c->fifo_head != CF_DNS_NIL)
        evict_as_unanswered(c, c->fifo_head, &c->stats.query_unanswered);

    free(c->entries);
    free(c->buckets);
    free(c);
}

void cf_dns_correlator_on_query(cf_dns_correlator_t *c, const cf_dns_txn_key_t *key,
                                int64_t observed_time_unix_nano, void *query_ctx)
{
    uint64_t h;
    int32_t  idx;

    if (!c || !key)
        return;

    /* Amortized timeout eviction, using this query's capture time as "now". */
    evict_expired(c, observed_time_unix_nano, CF_DNS_AMORTIZED_EVICT_MAX);

    h = key_hash(key);

    /* Same key already pending (retransmit / port reuse before timeout):
     * evict the older one as UNANSWERED and replace it in place. */
    idx = entry_find(c, key, h);
    if (idx != CF_DNS_NIL) {
        void *old_ctx = c->entries[idx].query_ctx;

        c->stats.pending_evicted_collision++;
        c->emit(c->user, CF_DNS_TXN_UNANSWERED, old_ctx, NULL, 0, 0, &c->entries[idx].key);

        c->entries[idx].key = *key;
        c->entries[idx].observed_time = observed_time_unix_nano;
        c->entries[idx].query_ctx = query_ctx;
        /* Re-thread as newest so it ages from now (bucket unchanged: same key). */
        fifo_unlink(c, idx);
        fifo_append(c, idx);
        return;
    }

    /* Need a fresh slot. */
    if (c->free_head == CF_DNS_NIL) {
        if (c->on_table_full == CF_DNS_ON_FULL_DROP_OLDEST && c->fifo_head != CF_DNS_NIL) {
            /* Make room by dropping the oldest pending (table-full drop). */
            evict_as_unanswered(c, c->fifo_head, &c->stats.pending_drop);
        } else {
            /* drop_newest (default): drop the just-arrived query, but still
             * hand its context back so it is released, never leaked. */
            c->stats.pending_drop++;
            c->emit(c->user, CF_DNS_TXN_UNANSWERED, query_ctx, NULL, 0, 0, key);
            return;
        }
    }

    idx = c->free_head;
    c->free_head = c->entries[idx].hnext;

    c->entries[idx].key = *key;
    c->entries[idx].observed_time = observed_time_unix_nano;
    c->entries[idx].query_ctx = query_ctx;
    c->entries[idx].hnext = c->buckets[bucket_of(c, h)];
    c->buckets[bucket_of(c, h)] = idx;
    fifo_append(c, idx);
    c->count++;
}

void cf_dns_correlator_on_response(cf_dns_correlator_t *c, const cf_dns_txn_key_t *key,
                                   int64_t observed_time_unix_nano, void *response_ctx)
{
    uint64_t h;
    int32_t  idx;

    if (!c || !key)
        return;

    h = key_hash(key);
    idx = entry_find(c, key, h);

    if (idx == CF_DNS_NIL) {
        /* No pending query: a capture gap, or a spoofing/poisoning signal. */
        c->stats.response_unmatched++;
        c->emit(c->user, CF_DNS_TXN_UNMATCHED, NULL, response_ctx, 0, 0, key);
        return;
    }

    {
        void            *query_ctx = c->entries[idx].query_ctx;
        cf_dns_txn_key_t mkey = c->entries[idx].key;
        int64_t          rtt = observed_time_unix_nano - c->entries[idx].observed_time;
        int              rtt_valid;

        /* DNS-D9: negative (clock skew / reordering) or implausibly large
         * (older than the query timeout) RTT is flagged unset. */
        if (rtt < 0 || rtt > c->query_timeout_nanos) {
            rtt_valid = 0;
            c->stats.rtt_invalid++;
        } else {
            rtt_valid = 1;
        }

        entry_release(c, idx);
        c->stats.transactions_observed++;
        c->emit(c->user, CF_DNS_TXN_OBSERVED, query_ctx, response_ctx, rtt, rtt_valid, &mkey);
    }
}

void cf_dns_correlator_tick(cf_dns_correlator_t *c, int64_t now_unix_nano)
{
    if (!c)
        return;

    /* Drain every expired entry; the FIFO is time-ordered so this stops at
     * the first live entry. SIZE_MAX budget = "all expired". */
    evict_expired(c, now_unix_nano, (size_t)-1);
}

void cf_dns_correlator_stats(const cf_dns_correlator_t *c, cf_dns_correlator_stats_t *out)
{
    if (!c || !out)
        return;

    *out = c->stats;
    out->pending_depth = c->count;
}
