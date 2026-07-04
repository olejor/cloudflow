#define _GNU_SOURCE

#include "dns_stage.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cf_decap.h"
#include "cf_dns.h"
#include "cf_ipfmt.h"
#include "cf_parse_util.h" /* cf_warn_list_t */

#include "cloudflow/v1/envelope.pb-c.h"

#include "cf_event_id.h"
#include "cf_log.h"
#include "cf_stats.h"
#include "cf_sync.h"
#include "cf_time.h"

#include "cf_rx_stats.h" /* CF_PACKET_FLAG_TRUNCATED */

/* Amortized correlator tick cadence: every N processed frames the stage runs a
 * timeout eviction sweep so a busy but one-sided table (all queries, no
 * responses) still drains without waiting for the periodic thread tick. */
#define DNS_STAGE_TICK_EVERY 64u

/* ------------------------------------------------------------------------
 * Normalized L2..L4 view. cf_decap_udp() and cf_decap_tcp() return different
 * structs; the stage collapses whichever succeeded into this one shape so the
 * PacketObservation builder and key builder do not each need a UDP and a TCP
 * variant. `dns`/`dns_len` is the bare DNS message (TCP length prefix already
 * stripped), the input cf_dns_parse() consumes.
 */
typedef struct {
    uint8_t  transport;              /* 0 = udp, 1 = tcp */
    /* link */
    uint8_t  src_mac[6], dst_mac[6];
    uint32_t vlan_ids[2];
    uint8_t  vlan_count;
    uint16_t ethertype;
    /* network */
    uint8_t  ip_version;
    uint8_t  src_ip[16], dst_ip[16];
    uint8_t  next_header;
    uint8_t  ttl_or_hop_limit;
    uint8_t  dscp, ecn;
    uint8_t  fragmented;
    uint16_t fragment_offset;
    /* transport */
    uint16_t src_port, dst_port;
    uint16_t udp_length;
    uint8_t  udp_checksum_present;
    uint8_t  tcp_flags;
    uint32_t tcp_payload_len;         /* raw TCP payload length (incl. prefix) */
    /* bare DNS message */
    const uint8_t *dns;
    size_t   dns_len;
} dns_l2l4_t;

/* Per-frame heap context handed to the correlator and back through exactly one
 * emit() (correlation.h ownership contract). Owns the parsed message, the
 * PacketObservation, the accumulated parser warnings, and a copy of the raw
 * captured frame (the DNS-D3 event_id hashes over it). On emit these children
 * are either transferred into the DnsTransactionEvent (which then owns/frees
 * them) or freed by dns_ctx_free(). */
typedef struct {
    Cloudflow__V1__DnsMessage        *msg;
    Cloudflow__V1__PacketObservation *pobs;
    Cloudflow__V1__ParserWarning    **warnings;
    size_t                            n_warnings;
    Cloudflow__V1__DnsLeg             role;
    uint32_t                          rcode;   /* folded header rcode */
    uint32_t                          qtype;   /* first question qtype, 0 if none */
    int64_t                           observed_time;
    uint8_t                          *frame;   /* raw captured bytes */
    uint32_t                          frame_len;
} dns_ctx_t;

struct dns_stage {
    dns_stage_config_t   cfg;      /* copied by value; pointer fields borrowed */
    cf_dns_leg_config_t  leg;      /* {local_addrs, backend_addrs} from cfg */
    cf_dns_correlator_t *correlator;
    uint64_t             processed;

    /* Last-synced snapshot of the correlator's CUMULATIVE loss counters. The
     * correlator rightly keeps running totals; dns_stage_sync_stats() ADDs
     * only the delta since this snapshot into the shared stats, so those
     * counters honor stats.reset_on_report (CF_ATOMIC_READ_AND_ZERO in
     * cf_dns_stats_report) exactly like every other counter -- per-interval
     * when reset, cumulative when not. */
    cf_dns_correlator_stats_t synced;
};

/* ------------------------------------------------------------------------
 * Small heap helpers, mirroring the DHCP formatter: every string or bytes
 * field assigned into a generated struct is a plain heap allocation (or the
 * empty sentinel), so cloudflow__v1__..._free_unpacked() frees the whole
 * hand-built tree exactly as if it had come from ..._unpack().
 */

static char *dns_dup_str(const char *s)
{
    return strdup(s ? s : "");
}

static void dns_free_warn_array(Cloudflow__V1__ParserWarning **items, size_t n)
{
    size_t i;

    if (!items)
        return;
    for (i = 0; i < n; i++)
        if (items[i])
            cloudflow__v1__parser_warning__free_unpacked(items[i], NULL);
    free(items);
}

static void dns_ctx_free(dns_ctx_t *c)
{
    if (!c)
        return;
    if (c->msg)
        cloudflow__v1__dns_message__free_unpacked(c->msg, NULL);
    if (c->pobs)
        cloudflow__v1__packet_observation__free_unpacked(c->pobs, NULL);
    dns_free_warn_array(c->warnings, c->n_warnings);
    free(c->frame);
    free(c);
}

/* ------------------------------------------------------------------------
 * PacketObservation (+ link/network/transport) builder from the normalized
 * decap view. Each helper returns NULL on allocation failure, having freed
 * what it partially built (relying on the generated __free_unpacked() for a
 * fully-formed struct with a child yet to fail underneath it), exactly like
 * the DHCP formatter's builders.
 */

static Cloudflow__V1__TransportLayerObservation *dns_build_transport(const dns_l2l4_t *d)
{
    Cloudflow__V1__TransportLayerObservation *t = calloc(1, sizeof(*t));

    if (!t)
        return NULL;
    cloudflow__v1__transport_layer_observation__init(t);

    t->src_port = d->src_port;
    t->dst_port = d->dst_port;

    if (d->transport == 1) {
        Cloudflow__V1__TcpObservation *tcp = calloc(1, sizeof(*tcp));

        if (!tcp) {
            free(t);
            return NULL;
        }
        cloudflow__v1__tcp_observation__init(tcp);
        tcp->flags = d->tcp_flags;
        tcp->payload_len = d->tcp_payload_len;

        t->protocol = CLOUDFLOW__V1__TRANSPORT_LAYER_OBSERVATION__TRANSPORT_PROTOCOL__TRANSPORT_PROTOCOL_TCP;
        t->ip_protocol_number = d->next_header;
        t->details_case = CLOUDFLOW__V1__TRANSPORT_LAYER_OBSERVATION__DETAILS_TCP;
        t->tcp = tcp;
    } else {
        Cloudflow__V1__UdpObservation *udp = calloc(1, sizeof(*udp));

        if (!udp) {
            free(t);
            return NULL;
        }
        cloudflow__v1__udp_observation__init(udp);
        udp->length = d->udp_length;
        udp->checksum_present = d->udp_checksum_present ? 1 : 0;

        t->protocol = CLOUDFLOW__V1__TRANSPORT_LAYER_OBSERVATION__TRANSPORT_PROTOCOL__TRANSPORT_PROTOCOL_UDP;
        t->ip_protocol_number = IPPROTO_UDP;
        t->details_case = CLOUDFLOW__V1__TRANSPORT_LAYER_OBSERVATION__DETAILS_UDP;
        t->udp = udp;
    }

    return t;
}

static Cloudflow__V1__NetworkLayerObservation *dns_build_network(const dns_l2l4_t *d)
{
    Cloudflow__V1__NetworkLayerObservation *n = calloc(1, sizeof(*n));
    char ipbuf[46];

    if (!n)
        return NULL;
    cloudflow__v1__network_layer_observation__init(n);

    if (d->ip_version == 4)
        n->protocol = CLOUDFLOW__V1__NETWORK_LAYER_OBSERVATION__NETWORK_PROTOCOL__NETWORK_PROTOCOL_IPV4;
    else if (d->ip_version == 6)
        n->protocol = CLOUDFLOW__V1__NETWORK_LAYER_OBSERVATION__NETWORK_PROTOCOL__NETWORK_PROTOCOL_IPV6;
    else
        n->protocol = CLOUDFLOW__V1__NETWORK_LAYER_OBSERVATION__NETWORK_PROTOCOL__NETWORK_PROTOCOL_UNSPECIFIED;

    cf_format_ip(ipbuf, d->ip_version, d->src_ip);
    n->src_ip = dns_dup_str(ipbuf);
    cf_format_ip(ipbuf, d->ip_version, d->dst_ip);
    n->dst_ip = dns_dup_str(ipbuf);

    n->next_header = d->next_header;
    n->ttl_or_hop_limit = d->ttl_or_hop_limit;
    n->dscp = d->dscp;
    n->ecn = d->ecn;
    n->fragmented = d->fragmented ? 1 : 0;
    n->fragment_offset = d->fragment_offset;

    if (!n->src_ip || !n->dst_ip) {
        cloudflow__v1__network_layer_observation__free_unpacked(n, NULL);
        return NULL;
    }

    return n;
}

static Cloudflow__V1__LinkLayerObservation *dns_build_link(const dns_l2l4_t *d)
{
    Cloudflow__V1__LinkLayerObservation *l = calloc(1, sizeof(*l));
    char macbuf[18];

    if (!l)
        return NULL;
    cloudflow__v1__link_layer_observation__init(l);

    cf_format_mac(macbuf, d->src_mac);
    l->src_mac = dns_dup_str(macbuf);
    cf_format_mac(macbuf, d->dst_mac);
    l->dst_mac = dns_dup_str(macbuf);
    l->ethertype = d->ethertype;

    if (d->vlan_count > 0) {
        size_t i;

        l->vlan_ids = malloc((size_t)d->vlan_count * sizeof(*l->vlan_ids));
        if (l->vlan_ids) {
            l->n_vlan_ids = d->vlan_count;
            for (i = 0; i < d->vlan_count; i++)
                l->vlan_ids[i] = d->vlan_ids[i];
        }
    }

    if (!l->src_mac || !l->dst_mac || (d->vlan_count > 0 && !l->vlan_ids)) {
        cloudflow__v1__link_layer_observation__free_unpacked(l, NULL);
        return NULL;
    }

    return l;
}

static Cloudflow__V1__PacketObservation *dns_build_pobs(const cf_packet_item_t *pkt,
                                                        const dns_l2l4_t *d)
{
    Cloudflow__V1__PacketObservation *p = calloc(1, sizeof(*p));

    if (!p)
        return NULL;
    cloudflow__v1__packet_observation__init(p);

    p->observed_time_unix_nano = pkt->observed_time_unix_nano;
    p->link = dns_build_link(d);
    p->network = dns_build_network(d);
    p->transport = dns_build_transport(d);

    if (!p->link || !p->network || !p->transport) {
        cloudflow__v1__packet_observation__free_unpacked(p, NULL);
        return NULL;
    }

    p->packet_len = pkt->packet_len;
    p->captured_len = pkt->captured_len;
    p->truncated = (pkt->flags & CF_PACKET_FLAG_TRUNCATED) ? 1 : 0;

    return p;
}

/* ------------------------------------------------------------------------
 * Decap: udp/53 first, tcp/53 on CF_DECAP_NOT_UDP. Fills *out and returns 0
 * on a usable bare DNS message, or 1 (counted) for a frame the stage cannot
 * decode: a non-UDP/non-TCP shape, a truncated/unsupported frame, or a
 * multi-segment DNS-over-TCP message (DNS-D1: never reassembled). */
static int dns_decode_frame(dns_stage_t *s, const cf_packet_item_t *pkt, dns_l2l4_t *out)
{
    cf_dns_source_stats_t *st = s->cfg.stats;
    cf_decap_udp_t u;
    cf_decap_result_t ru;

    memset(out, 0, sizeof(*out));

    ru = cf_decap_udp(pkt->data, pkt->captured_len, &u);
    if (ru == CF_DECAP_OK) {
        out->transport = 0;
        memcpy(out->src_mac, u.src_mac, 6);
        memcpy(out->dst_mac, u.dst_mac, 6);
        out->vlan_ids[0] = u.vlan_ids[0];
        out->vlan_ids[1] = u.vlan_ids[1];
        out->vlan_count = u.vlan_count;
        out->ethertype = u.ethertype;
        out->ip_version = u.ip_version;
        memcpy(out->src_ip, u.src_ip, 16);
        memcpy(out->dst_ip, u.dst_ip, 16);
        out->next_header = u.next_header;
        out->ttl_or_hop_limit = u.ttl_or_hop_limit;
        out->dscp = u.dscp;
        out->ecn = u.ecn;
        out->fragmented = u.fragmented;
        out->fragment_offset = u.fragment_offset;
        out->src_port = u.src_port;
        out->dst_port = u.dst_port;
        out->udp_length = u.udp_length;
        out->udp_checksum_present = u.udp_checksum_present;
        out->dns = u.payload;
        out->dns_len = u.payload_len;
        return 0;
    }

    if (ru == CF_DECAP_NOT_UDP) {
        cf_decap_tcp_t t;
        cf_decap_result_t rt = cf_decap_tcp(pkt->data, pkt->captured_len, &t);
        uint16_t declared;
        size_t avail;

        if (rt != CF_DECAP_OK) {
            if (st)
                CF_ATOMIC_INC(st->packets_skipped_total);
            return 1;
        }

        /* Strip the RFC 1035 2-byte big-endian length prefix. */
        if (t.payload_len < 2) {
            if (st)
                CF_ATOMIC_INC(st->packets_skipped_total);
            return 1;
        }
        declared = (uint16_t)((t.payload[0] << 8) | t.payload[1]);
        avail = t.payload_len - 2;
        if (declared > avail) {
            /* Multi-segment message: no decoded body, never reassembled. */
            if (st)
                CF_ATOMIC_INC(st->dns_tcp_partial_total);
            return 1;
        }

        out->transport = 1;
        memcpy(out->src_mac, t.src_mac, 6);
        memcpy(out->dst_mac, t.dst_mac, 6);
        out->vlan_ids[0] = t.vlan_ids[0];
        out->vlan_ids[1] = t.vlan_ids[1];
        out->vlan_count = t.vlan_count;
        out->ethertype = t.ethertype;
        out->ip_version = t.ip_version;
        memcpy(out->src_ip, t.src_ip, 16);
        memcpy(out->dst_ip, t.dst_ip, 16);
        out->next_header = t.next_header;
        out->ttl_or_hop_limit = t.ttl_or_hop_limit;
        out->dscp = t.dscp;
        out->ecn = t.ecn;
        out->fragmented = t.fragmented;
        out->fragment_offset = t.fragment_offset;
        out->src_port = t.src_port;
        out->dst_port = t.dst_port;
        out->tcp_flags = t.tcp_flags;
        out->tcp_payload_len = (uint32_t)t.payload_len;
        out->dns = t.payload + 2;
        out->dns_len = declared;
        return 0;
    }

    /* CF_DECAP_TRUNCATED / CF_DECAP_UNSUPPORTED. */
    if (st)
        CF_ATOMIC_INC(st->packets_skipped_total);
    return 1;
}

/* ------------------------------------------------------------------------
 * DNS-D6 correlation key: canonicalize so a query and its response map to the
 * SAME key -- client is the non-:53 endpoint, server is the :53 endpoint.
 */
static void dns_build_key(cf_dns_txn_key_t *key, const dns_l2l4_t *d,
                          const Cloudflow__V1__DnsMessage *msg, int local_is_server)
{
    const uint8_t *client_ip, *server_ip;
    uint16_t client_port, server_port;

    memset(key, 0, sizeof(*key));

    if (d->dst_port == 53) {
        server_ip = d->dst_ip;
        server_port = d->dst_port;
        client_ip = d->src_ip;
        client_port = d->src_port;
    } else if (d->src_port == 53) {
        server_ip = d->src_ip;
        server_port = d->src_port;
        client_ip = d->dst_ip;
        client_port = d->dst_port;
    } else {
        /* Neither endpoint is :53 (BPF slippage): pick a stable canonical
         * orientation so both halves still agree -- dst is "server". */
        server_ip = d->dst_ip;
        server_port = d->dst_port;
        client_ip = d->src_ip;
        client_port = d->src_port;
    }

    key->transport = d->transport;
    key->local_is_server = (uint8_t)(local_is_server ? 1 : 0);
    key->ip_version = d->ip_version;
    memcpy(key->client_ip, client_ip, sizeof(key->client_ip));
    memcpy(key->server_ip, server_ip, sizeof(key->server_ip));
    key->client_port = client_port;
    key->server_port = server_port;

    if (msg->header)
        key->dns_id = (uint16_t)msg->header->id;

    if (msg->n_questions > 0 && msg->questions && msg->questions[0]) {
        const Cloudflow__V1__DnsQuestion *q0 = msg->questions[0];
        const char *qn = q0->qname ? q0->qname : "";
        size_t n = strlen(qn);
        size_t i;

        key->qtype = (uint16_t)q0->qtype;
        key->qclass = (uint16_t)q0->qclass;

        if (n > sizeof(key->qname_canonical))
            n = sizeof(key->qname_canonical);
        for (i = 0; i < n; i++) {
            uint8_t c = (uint8_t)qn[i];

            if (c >= 'A' && c <= 'Z') /* 0x20 normalization (defensive) */
                c = (uint8_t)(c + 32);
            key->qname_canonical[i] = c;
        }
        key->qname_len = (uint16_t)n;
    }
}

/* Stable per-transaction sampling key: a hash over the DNS-D6 key material, so
 * replaying the same capture yields the same emit/drop decisions (sampling.h
 * mixes it further with splitmix64). */
static uint64_t dns_key_sample_hash(const cf_dns_txn_key_t *k)
{
    uint64_t h = 1469598103934665603ULL; /* FNV-1a offset basis */
    size_t   qn = k->qname_len;
    size_t   i;

    if (qn > sizeof(k->qname_canonical))
        qn = sizeof(k->qname_canonical);

#define DNS_SH_BYTE(b)                                                          \
    do {                                                                       \
        h ^= (uint64_t)(uint8_t)(b);                                           \
        h *= 1099511628211ULL;                                                 \
    } while (0)

    DNS_SH_BYTE(k->transport);
    DNS_SH_BYTE(k->local_is_server);
    DNS_SH_BYTE(k->ip_version);
    for (i = 0; i < sizeof(k->client_ip); i++)
        DNS_SH_BYTE(k->client_ip[i]);
    for (i = 0; i < sizeof(k->server_ip); i++)
        DNS_SH_BYTE(k->server_ip[i]);
    DNS_SH_BYTE(k->client_port & 0xff);
    DNS_SH_BYTE(k->client_port >> 8);
    DNS_SH_BYTE(k->server_port & 0xff);
    DNS_SH_BYTE(k->server_port >> 8);
    DNS_SH_BYTE(k->dns_id & 0xff);
    DNS_SH_BYTE(k->dns_id >> 8);
    DNS_SH_BYTE(k->qtype & 0xff);
    DNS_SH_BYTE(k->qtype >> 8);
    DNS_SH_BYTE(k->qclass & 0xff);
    DNS_SH_BYTE(k->qclass >> 8);
    for (i = 0; i < qn; i++)
        DNS_SH_BYTE(k->qname_canonical[i]);

#undef DNS_SH_BYTE
    return h;
}

/* Human-readable DNS-D6 provenance string, e.g.
 * "udp 192.0.2.10:40000->192.0.2.53:53 id=4660 www.example.com/1/1". Written
 * into `out` (bounded). */
static void dns_format_txn_key(char *out, size_t out_len, const cf_dns_txn_key_t *k)
{
    char client[46], server[46];
    char qname[257];
    size_t qn = k->qname_len;

    if (qn > sizeof(k->qname_canonical))
        qn = sizeof(k->qname_canonical);
    if (qn > sizeof(qname) - 1)
        qn = sizeof(qname) - 1;
    memcpy(qname, k->qname_canonical, qn);
    qname[qn] = '\0';

    cf_format_ip(client, k->ip_version, k->client_ip);
    cf_format_ip(server, k->ip_version, k->server_ip);

    snprintf(out, out_len, "%s %s:%u->%s:%u id=%u %s/%u/%u",
             k->transport == 1 ? "tcp" : "udp",
             client, (unsigned)k->client_port, server, (unsigned)k->server_port,
             (unsigned)k->dns_id, qname, (unsigned)k->qtype, (unsigned)k->qclass);
}

/* ------------------------------------------------------------------------
 * D11 oversize handling: drop a DnsMessage's raw payload, set the truncated
 * flag. Same shape as the DHCP formatter's clear_raw_payload(). */
static void dns_clear_raw_payload(Cloudflow__V1__DnsMessage *m)
{
    if (!m)
        return;
    free(m->raw_dns_payload.data);
    m->raw_dns_payload.data = NULL;
    m->raw_dns_payload.len = 0;
    m->raw_payload_truncated = 1;
}

/* Snapshot the correlator's DNS-D8 loss counters into the shared stats line
 * (the correlator counts them; the stage surfaces them). Cheap; called after
 * every emit / process / tick. */
static void dns_stage_sync_stats(dns_stage_t *s)
{
    cf_dns_correlator_stats_t cs;
    cf_dns_source_stats_t *st = s->cfg.stats;

    if (!st)
        return;

    cf_dns_correlator_stats(s->correlator, &cs);

    /* The correlator holds CUMULATIVE totals. Publish only the delta since the
     * last sync via CF_ATOMIC_ADD so these counters honor stats.reset_on_report
     * (cf_dns_stats_report reads them with CF_ATOMIC_READ_AND_ZERO when reset):
     * a re-STORE of the cumulative value would make the next read re-observe
     * all prior counts, so reset_on_report could never zero them. ADD-of-delta
     * yields correct per-interval values under reset and still accumulates
     * correctly without it. */
    CF_ATOMIC_ADD(st->dns_query_unanswered_total,
                  (unsigned long)(cs.query_unanswered - s->synced.query_unanswered));
    CF_ATOMIC_ADD(st->dns_response_unmatched_total,
                  (unsigned long)(cs.response_unmatched - s->synced.response_unmatched));
    CF_ATOMIC_ADD(st->dns_pending_drop_total,
                  (unsigned long)(cs.pending_drop - s->synced.pending_drop));
    CF_ATOMIC_ADD(st->dns_pending_evicted_collision_total,
                  (unsigned long)(cs.pending_evicted_collision - s->synced.pending_evicted_collision));
    CF_ATOMIC_ADD(st->dns_rtt_invalid_total,
                  (unsigned long)(cs.rtt_invalid - s->synced.rtt_invalid));
    s->synced = cs;

    /* A true gauge (current pending-table occupancy): STORE the live value. */
    CF_ATOMIC_STORE(st->dns_pending_table_depth, (unsigned long)cs.pending_depth);
}

/* ------------------------------------------------------------------------
 * The emit callback: the encode/enqueue point. Invoked by the correlator once
 * per decided transaction with the query and/or response contexts. Applies the
 * sampling policy, builds the CloudFlowEvent, enforces the D11 cap, packs and
 * pushes it, and frees the context(s). It owns and frees every context handed
 * to it (ownership contract in correlation.h).
 */
static void dns_stage_emit(void *user, cf_dns_txn_outcome_t outcome,
                           void *query_ctx, void *response_ctx,
                           int64_t rtt_nanos, int rtt_valid,
                           const cf_dns_txn_key_t *key)
{
    dns_stage_t *s = user;
    cf_dns_source_stats_t *st = s->cfg.stats;
    dns_ctx_t *q = query_ctx;
    dns_ctx_t *r = response_ctx;
    dns_ctx_t *primary = q ? q : r;

    Cloudflow__V1__DnsTransactionEvent *txn;
    Cloudflow__V1__EventEnvelope *env;
    Cloudflow__V1__CloudFlowEvent *ev;
    Cloudflow__V1__DnsLeg role;
    const char *event_type;
    char idbuf[CF_EVENT_ID_LEN];
    char keybuf[400];
    char ipbuf[46];
    size_t packed;
    cf_event_item_t item;

    if (!primary) /* defensive: correlator always sets at least one context */
        return;

    role = primary->role;

    switch (outcome) {
    case CF_DNS_TXN_OBSERVED:   event_type = "dns.transaction.observed"; break;
    case CF_DNS_TXN_UNANSWERED: event_type = "dns.query.unanswered";     break;
    default:                    event_type = "dns.response.unmatched";   break;
    }

    /* ---- sampling / emit policy (DNS-D8) --------------------------------- */
    {
        cf_dns_emit_facts_t f;

        f.outcome = outcome;
        f.rcode = r ? r->rcode : (q ? q->rcode : 0);
        f.qtype = q ? q->qtype : (r ? r->qtype : 0);
        f.has_response = (r != NULL);
        f.sample_key = dns_key_sample_hash(key);

        if (!cf_dns_emit_decide(&s->cfg.emit_policy, &f)) {
            if (st)
                CF_ATOMIC_INC(st->dns_sampled_out_total);
            dns_ctx_free(q);
            dns_ctx_free(r);
            dns_stage_sync_stats(s);
            return;
        }
    }

    /* ---- DnsTransactionEvent: steal the contexts' children into it ------- */
    txn = calloc(1, sizeof(*txn));
    if (!txn) {
        dns_ctx_free(q);
        dns_ctx_free(r);
        dns_stage_sync_stats(s);
        return;
    }
    cloudflow__v1__dns_transaction_event__init(txn);

    if (q) {
        txn->query_packet = q->pobs; q->pobs = NULL;
        txn->query = q->msg;         q->msg = NULL;
    }
    if (r) {
        txn->response_packet = r->pobs; r->pobs = NULL;
        txn->response = r->msg;         r->msg = NULL;
    }

    /* Merge the query and response parser warnings into the event. */
    {
        size_t nq = q ? q->n_warnings : 0;
        size_t nr = r ? r->n_warnings : 0;
        size_t total = nq + nr;

        if (total > 0) {
            Cloudflow__V1__ParserWarning **arr = malloc(total * sizeof(*arr));

            if (arr) {
                size_t j = 0, i;

                for (i = 0; i < nq; i++)
                    arr[j++] = q->warnings[i];
                for (i = 0; i < nr; i++)
                    arr[j++] = r->warnings[i];
                txn->parser_warnings = arr;
                txn->n_parser_warnings = total;
                /* The elements now belong to txn; drop the ctx backing arrays
                 * (but not the elements). */
                if (q) { free(q->warnings); q->warnings = NULL; q->n_warnings = 0; }
                if (r) { free(r->warnings); r->warnings = NULL; r->n_warnings = 0; }
            }
            /* On malloc failure the warnings stay with the contexts and are
             * freed by dns_ctx_free() below -- the event simply loses them. */
        }
    }

    txn->role = role;
    txn->rtt_nanos = rtt_nanos;
    txn->rtt_valid = rtt_valid ? 1 : 0;

    dns_format_txn_key(keybuf, sizeof(keybuf), key);
    txn->transaction_key = dns_dup_str(keybuf);

    cf_format_ip(ipbuf, key->ip_version, key->client_ip);
    txn->client_ip = dns_dup_str(ipbuf);
    txn->client_port = key->client_port;
    cf_format_ip(ipbuf, key->ip_version, key->server_ip);
    txn->server_ip = dns_dup_str(ipbuf);

    /* WP-DNS11a: tag the transaction with the operator's service role for the
     * server-side address. Only when the server side is determinate (role !=
     * UNKNOWN, i.e. one endpoint genuinely owned :53) and the address is mapped;
     * otherwise the field stays empty (dns_dup_str(NULL) -> ""). It is an
     * additional operator dimension and never changes the leg role above. */
    {
        const char *service_role = NULL;

        if (role != CLOUDFLOW__V1__DNS_LEG__DNS_LEG_UNKNOWN && s->cfg.role_map)
            service_role = cf_dns_role_lookup(s->cfg.role_map, key->ip_version, key->server_ip);
        txn->service_role = dns_dup_str(service_role);
    }

    if (!txn->transaction_key || !txn->client_ip || !txn->server_ip || !txn->service_role) {
        cloudflow__v1__dns_transaction_event__free_unpacked(txn, NULL);
        dns_ctx_free(q);
        dns_ctx_free(r);
        dns_stage_sync_stats(s);
        return;
    }

    /* ---- EventEnvelope (DNS-D3 event_id over the primary packet) --------- */
    env = calloc(1, sizeof(*env));
    if (!env) {
        cloudflow__v1__dns_transaction_event__free_unpacked(txn, NULL);
        dns_ctx_free(q);
        dns_ctx_free(r);
        dns_stage_sync_stats(s);
        return;
    }
    cloudflow__v1__event_envelope__init(env);

    cf_event_id(idbuf, s->cfg.source_host, s->cfg.capture_interface,
                primary->observed_time, primary->frame, primary->frame_len);

    env->event_id = dns_dup_str(idbuf);
    env->schema_version = 1;
    env->source_type = dns_dup_str("dns");
    env->source_host = dns_dup_str(s->cfg.source_host);
    env->source_instance = dns_dup_str(s->cfg.source_instance);
    env->capture_interface = dns_dup_str(s->cfg.capture_interface);
    env->observation_method = dns_dup_str(s->cfg.observation_method);
    env->observed_time_unix_nano = primary->observed_time;
    env->ingest_time_unix_nano = cf_now_unix_nano();
    env->event_type = dns_dup_str(event_type);
    env->visibility = CLOUDFLOW__V1__VISIBILITY_LEVEL__VISIBILITY_PACKET_PAYLOAD;
    env->confidence = CLOUDFLOW__V1__OBSERVATION_CONFIDENCE__OBSERVATION_CONFIDENCE_OBSERVED;
    env->payload_schema = dns_dup_str("cloudflow.v1.DnsTransactionEvent");
    env->stream_name = dns_dup_str(cf_stream_name(CF_STREAM_DNS));

    if (!env->event_id || !env->source_type || !env->source_host ||
        !env->source_instance || !env->capture_interface || !env->observation_method ||
        !env->event_type || !env->payload_schema || !env->stream_name) {
        cloudflow__v1__event_envelope__free_unpacked(env, NULL);
        cloudflow__v1__dns_transaction_event__free_unpacked(txn, NULL);
        dns_ctx_free(q);
        dns_ctx_free(r);
        dns_stage_sync_stats(s);
        return;
    }

    /* ---- CloudFlowEvent -------------------------------------------------- */
    ev = calloc(1, sizeof(*ev));
    if (!ev) {
        cloudflow__v1__event_envelope__free_unpacked(env, NULL);
        cloudflow__v1__dns_transaction_event__free_unpacked(txn, NULL);
        dns_ctx_free(q);
        dns_ctx_free(r);
        dns_stage_sync_stats(s);
        return;
    }
    cloudflow__v1__cloud_flow_event__init(ev);
    ev->envelope = env;
    ev->payload_case = CLOUDFLOW__V1__CLOUD_FLOW_EVENT__PAYLOAD_DNS_TRANSACTION;
    ev->dns_transaction = txn;

    /* ---- D11 size cap ---------------------------------------------------- */
    packed = cloudflow__v1__cloud_flow_event__get_packed_size(ev);
    if (packed > CLOUDFLOW_EVENT_MAX_SIZE) {
        dns_clear_raw_payload(txn->query);
        dns_clear_raw_payload(txn->response);
        packed = cloudflow__v1__cloud_flow_event__get_packed_size(ev);
    }
    if (packed > CLOUDFLOW_EVENT_MAX_SIZE) {
        if (st)
            CF_ATOMIC_INC(st->events_oversize_dropped_total);
        cloudflow__v1__cloud_flow_event__free_unpacked(ev, NULL);
        dns_ctx_free(q);
        dns_ctx_free(r);
        dns_stage_sync_stats(s);
        return;
    }

    /* ---- pack + push ----------------------------------------------------- */
    memset(&item, 0, sizeof(item));
    item.payload_len = (uint32_t)cloudflow__v1__cloud_flow_event__pack(ev, item.payload);
    if (item.payload_len == 0) {
        if (st)
            CF_ATOMIC_INC(st->protobuf_encode_failure_total);
        cloudflow__v1__cloud_flow_event__free_unpacked(ev, NULL);
        dns_ctx_free(q);
        dns_ctx_free(r);
        dns_stage_sync_stats(s);
        return;
    }
    item.observed_time_unix_nano = primary->observed_time;
    item.stream_id = CF_STREAM_DNS;
    item.protocol = CF_PROTO_DNS;
    {
        size_t n = strlen(event_type);

        if (n >= CLOUDFLOW_EVENT_TYPE_MAX)
            n = CLOUDFLOW_EVENT_TYPE_MAX - 1;
        memcpy(item.event_type, event_type, n);
        item.event_type[n] = '\0';
    }

    (void)cf_queue_push_policy(s->cfg.out, &item, sizeof(item), s->cfg.on_full,
                               st ? &st->formatter_queue_drop_total : NULL);

    if (st) {
        CF_ATOMIC_INC(st->dns_transactions_emitted_total);
        switch (role) {
        case CLOUDFLOW__V1__DNS_LEG__DNS_LEG_CLIENT_FACING:
            CF_ATOMIC_INC(st->dns_transactions_emitted_client_facing_total); break;
        case CLOUDFLOW__V1__DNS_LEG__DNS_LEG_BACKEND:
            CF_ATOMIC_INC(st->dns_transactions_emitted_backend_total); break;
        case CLOUDFLOW__V1__DNS_LEG__DNS_LEG_RECURSION_UPSTREAM:
            CF_ATOMIC_INC(st->dns_transactions_emitted_recursion_upstream_total); break;
        default:
            CF_ATOMIC_INC(st->dns_transactions_emitted_unknown_total); break;
        }
        CF_ATOMIC_STORE(st->formatter_queue_depth, cf_queue_length(s->cfg.out));
    }

    cloudflow__v1__cloud_flow_event__free_unpacked(ev, NULL);
    dns_ctx_free(q); /* msg/pobs/warnings already transferred; frees frame */
    dns_ctx_free(r);
    dns_stage_sync_stats(s);
}

/* ------------------------------------------------------------------------
 * Engine lifecycle + per-frame processing.
 */

dns_stage_t *dns_stage_new(const dns_stage_config_t *cfg)
{
    dns_stage_t *s;

    if (!cfg || !cfg->out || !cfg->stats)
        return NULL;

    s = calloc(1, sizeof(*s));
    if (!s)
        return NULL;

    s->cfg = *cfg;
    s->leg.local_addrs = cfg->local_addrs;
    s->leg.backend_addrs = cfg->backend_addrs;

    s->correlator = cf_dns_correlator_new(&cfg->correlator, dns_stage_emit, s);
    if (!s->correlator) {
        free(s);
        return NULL;
    }

    return s;
}

void dns_stage_free(dns_stage_t *s)
{
    if (!s)
        return;

    /* Drains every still-pending query as UNANSWERED through dns_stage_emit(),
     * so no context leaks. */
    cf_dns_correlator_free(s->correlator);
    free(s);
}

int dns_stage_process_packet(dns_stage_t *s, const cf_packet_item_t *pkt)
{
    cf_dns_source_stats_t *st;
    dns_l2l4_t d;
    cf_warn_list_t warnings;
    Cloudflow__V1__DnsMessage *msg = NULL;
    Cloudflow__V1__PacketObservation *pobs;
    dns_ctx_t *ctx;
    cf_dns_txn_key_t key;
    Cloudflow__V1__DnsLeg role;
    int local_is_server = 0;
    int is_response;

    if (!s || !pkt)
        return -1;

    st = s->cfg.stats;

    if (dns_decode_frame(s, pkt, &d) != 0)
        return 1; /* counted inside dns_decode_frame */

    cf_warn_list_init(&warnings);
    if (!cf_dns_parse(d.dns, d.dns_len, &msg, &warnings)) {
        size_t n = 0;
        Cloudflow__V1__ParserWarning **items = NULL;

        cf_warn_list_take(&warnings, &n, &items);
        dns_free_warn_array(items, n);
        if (st)
            CF_ATOMIC_INC(st->decode_parse_failure_total);
        return 1;
    }

    /* Preserve the wire bytes for a raw view, subject to the D11 cap (mirrors
     * the DHCP formatter's raw_dhcp_payload). */
    if (d.dns_len > 0) {
        msg->raw_dns_payload.data = malloc(d.dns_len);
        if (msg->raw_dns_payload.data) {
            memcpy(msg->raw_dns_payload.data, d.dns, d.dns_len);
            msg->raw_dns_payload.len = d.dns_len;
        }
    }

    role = cf_dns_classify_leg(&s->leg, d.ip_version, d.src_ip, d.src_port,
                               d.dst_ip, d.dst_port, CF_DNS_DIR_UNKNOWN,
                               &local_is_server);

    dns_build_key(&key, &d, msg, local_is_server);
    is_response = (msg->header && msg->header->qr) ? 1 : 0;

    pobs = dns_build_pobs(pkt, &d);
    if (!pobs) {
        size_t n = 0;
        Cloudflow__V1__ParserWarning **items = NULL;

        cloudflow__v1__dns_message__free_unpacked(msg, NULL);
        cf_warn_list_take(&warnings, &n, &items);
        dns_free_warn_array(items, n);
        if (st)
            CF_ATOMIC_INC(st->packets_skipped_total);
        return 1;
    }

    ctx = calloc(1, sizeof(*ctx));
    if (ctx)
        ctx->frame = malloc(pkt->captured_len ? pkt->captured_len : 1);
    if (!ctx || !ctx->frame) {
        size_t n = 0;
        Cloudflow__V1__ParserWarning **items = NULL;

        cloudflow__v1__dns_message__free_unpacked(msg, NULL);
        cloudflow__v1__packet_observation__free_unpacked(pobs, NULL);
        cf_warn_list_take(&warnings, &n, &items);
        dns_free_warn_array(items, n);
        free(ctx);
        if (st)
            CF_ATOMIC_INC(st->packets_skipped_total);
        return 1;
    }

    ctx->msg = msg;
    ctx->pobs = pobs;
    cf_warn_list_take(&warnings, &ctx->n_warnings, &ctx->warnings);
    ctx->role = role;
    ctx->rcode = msg->header ? msg->header->rcode : 0;
    ctx->qtype = key.qtype;
    ctx->observed_time = pkt->observed_time_unix_nano;
    ctx->frame_len = pkt->captured_len;
    memcpy(ctx->frame, pkt->data, pkt->captured_len);

    /* Feed the correlator; it hands ctx back through exactly one emit(). */
    if (is_response) {
        if (st)
            CF_ATOMIC_INC(st->dns_responses_parsed_total);
        cf_dns_correlator_on_response(s->correlator, &key, pkt->observed_time_unix_nano, ctx);
    } else {
        if (st)
            CF_ATOMIC_INC(st->dns_queries_parsed_total);
        cf_dns_correlator_on_query(s->correlator, &key, pkt->observed_time_unix_nano, ctx);
    }

    /* Amortized timeout eviction so a one-sided table still drains. */
    if (++s->processed % DNS_STAGE_TICK_EVERY == 0)
        cf_dns_correlator_tick(s->correlator, pkt->observed_time_unix_nano);

    dns_stage_sync_stats(s);
    return 0;
}

void dns_stage_tick(dns_stage_t *s, int64_t now_unix_nano)
{
    if (!s)
        return;
    cf_dns_correlator_tick(s->correlator, now_unix_nano);
    dns_stage_sync_stats(s);
}

/* ------------------------------------------------------------------------
 * dns_stage_start()/dns_stage_stop(): the pipeline-thread wrapper, mirroring
 * formatter_start()/formatter_stop(). Polls `in` with a 1ms backoff when
 * empty, ticks the correlator each idle iteration so a quiet table drains,
 * and on stop drains whatever is still queued before tearing down the engine
 * (which drains pending queries as unanswered).
 */

#define DNS_STAGE_POLL_SLEEP_NS (1000L * 1000L) /* 1 ms */

typedef struct {
    dns_stage_config_t cfg;
    dns_stage_t       *engine;
    pthread_t          thread;
    atomic_bool        started;
} dns_stage_thread_t;

static dns_stage_thread_t g_dns_stage;

static void dns_stage_drain(dns_stage_t *engine, cf_queue_t *in)
{
    cf_packet_item_t pkt;

    while (cf_queue_pop(in, &pkt) == 0)
        (void)dns_stage_process_packet(engine, &pkt);
}

static void *dns_stage_thread_main(void *arg)
{
    dns_stage_thread_t *state = arg;
    cf_packet_item_t pkt;

    pthread_setname_np(pthread_self(), "cf-dns-stage");
    cf_log(CF_LOG_INFO, "dns event-stage started", NULL);

    while (!cf_stop_notified()) {
        if (cf_queue_pop(state->cfg.in, &pkt) == 0) {
            (void)dns_stage_process_packet(state->engine, &pkt);
        } else {
            dns_stage_tick(state->engine, cf_now_unix_nano());
            cf_sleep_ns(DNS_STAGE_POLL_SLEEP_NS);
        }
    }

    /* Lossless shutdown: drain whatever is still queued. */
    dns_stage_drain(state->engine, state->cfg.in);

    cf_log(CF_LOG_INFO, "dns event-stage stopped", NULL);
    return NULL;
}

int dns_stage_start(const dns_stage_config_t *cfg)
{
    if (!cfg || !cfg->in || !cfg->out || !cfg->stats) {
        cf_log(CF_LOG_ERROR, "dns_stage_start: invalid config (in/out/stats required)", NULL);
        return -1;
    }
    if (atomic_load(&g_dns_stage.started)) {
        cf_log(CF_LOG_ERROR, "dns_stage_start: already started", NULL);
        return -1;
    }

    memset(&g_dns_stage, 0, sizeof(g_dns_stage));
    g_dns_stage.cfg = *cfg;

    g_dns_stage.engine = dns_stage_new(cfg);
    if (!g_dns_stage.engine) {
        cf_log(CF_LOG_ERROR, "dns_stage_start: engine allocation failed", NULL);
        return -1;
    }

    if (pthread_create(&g_dns_stage.thread, NULL, dns_stage_thread_main, &g_dns_stage) != 0) {
        cf_log(CF_LOG_ERROR, "dns_stage_start: pthread_create() failed", NULL);
        dns_stage_free(g_dns_stage.engine);
        g_dns_stage.engine = NULL;
        return -1;
    }

    atomic_store(&g_dns_stage.started, true);
    return 0;
}

void dns_stage_stop(void)
{
    if (!atomic_load(&g_dns_stage.started))
        return;

    cf_stop_notify(0);
    pthread_join(g_dns_stage.thread, NULL);

    /* Tears down the engine, draining still-pending queries as unanswered
     * through the same emit path. */
    dns_stage_free(g_dns_stage.engine);
    g_dns_stage.engine = NULL;

    atomic_store(&g_dns_stage.started, false);
}
