#define _GNU_SOURCE

#include "formatter.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "cf_decap.h"
#include "cf_dhcpv4.h"
#include "cf_dhcpv6.h"
#include "cf_ipfmt.h"
#include "cloudflow/v1/envelope.pb-c.h"

#include "cf_event_id.h"
#include "cf_log.h"
#include "cf_stats.h"
#include "cf_sync.h"
#include "cf_time.h"

#include "cf_rx_stats.h" /* CF_PACKET_FLAG_TRUNCATED */

/* ------------------------------------------------------------------------
 * Small heap-string/-bytes helpers. Every `char *`/ProtobufCBinaryData field
 * this file assigns into a generated struct is a plain heap allocation (or
 * NULL/{0,NULL} for an empty ProtobufCBinaryData), never a borrowed/`const`
 * pointer or a string literal -- that is what lets
 * cloudflow__v1__cloud_flow_event__free_unpacked() (a purely
 * descriptor-driven walk; see envelope.pb-c.c) free this whole hand-built
 * tree exactly as if it had come from ..._unpack(), matching the
 * convention cf_dhcpv4.c/cf_dhcpv6.c already use for the subtrees they
 * build (see cf_dhcpv4.h's header comment). */

static char *cfmt_dup_str(const char *s)
{
    return strdup(s ? s : "");
}

/* ------------------------------------------------------------------------
 * PacketObservation (+ link/network/transport/udp) builder, from the WP-05
 * decap result and the packet item's own length/flags fields. Every helper
 * returns NULL on allocation failure, having freed anything it partially
 * built itself first (build_packet_observation() below relies on
 * cloudflow__v1__packet_observation__free_unpacked() to clean up an already
 * fully-formed struct with only some children yet to fail underneath it).
 */

static Cloudflow__V1__UdpObservation *build_udp_observation(const cf_decap_udp_t *d)
{
    Cloudflow__V1__UdpObservation *udp = calloc(1, sizeof(*udp));

    if (!udp)
        return NULL;
    cloudflow__v1__udp_observation__init(udp);

    udp->length = d->udp_length;
    udp->checksum_present = d->udp_checksum_present ? 1 : 0;
    udp->checksum_validated = 0; /* not verified by cf_decap_udp */

    return udp;
}

static Cloudflow__V1__TransportLayerObservation *build_transport(const cf_decap_udp_t *d)
{
    Cloudflow__V1__TransportLayerObservation *t = calloc(1, sizeof(*t));

    if (!t)
        return NULL;
    cloudflow__v1__transport_layer_observation__init(t);

    t->protocol = CLOUDFLOW__V1__TRANSPORT_LAYER_OBSERVATION__TRANSPORT_PROTOCOL__TRANSPORT_PROTOCOL_UDP;
    t->ip_protocol_number = IPPROTO_UDP;
    t->src_port = d->src_port;
    t->dst_port = d->dst_port;
    t->details_case = CLOUDFLOW__V1__TRANSPORT_LAYER_OBSERVATION__DETAILS_UDP;
    t->udp = build_udp_observation(d);

    if (!t->udp) {
        free(t);
        return NULL;
    }

    return t;
}

static Cloudflow__V1__NetworkLayerObservation *build_network(const cf_decap_udp_t *d)
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
    n->src_ip = cfmt_dup_str(ipbuf);
    cf_format_ip(ipbuf, d->ip_version, d->dst_ip);
    n->dst_ip = cfmt_dup_str(ipbuf);

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

static Cloudflow__V1__LinkLayerObservation *build_link(const cf_decap_udp_t *d)
{
    Cloudflow__V1__LinkLayerObservation *l = calloc(1, sizeof(*l));
    char macbuf[18];

    if (!l)
        return NULL;
    cloudflow__v1__link_layer_observation__init(l);

    cf_format_mac(macbuf, d->src_mac);
    l->src_mac = cfmt_dup_str(macbuf);
    cf_format_mac(macbuf, d->dst_mac);
    l->dst_mac = cfmt_dup_str(macbuf);
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

static Cloudflow__V1__PacketObservation *build_packet_observation(const cf_packet_item_t *pkt,
                                                                    const cf_decap_udp_t *decap)
{
    Cloudflow__V1__PacketObservation *p = calloc(1, sizeof(*p));

    if (!p)
        return NULL;
    cloudflow__v1__packet_observation__init(p);

    p->observed_time_unix_nano = pkt->observed_time_unix_nano;
    p->link = build_link(decap);
    p->network = build_network(decap);
    p->transport = build_transport(decap);

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
 * EventEnvelope builder, per docs/dhcp-source.md's WP-10 section
 * and proto/cloudflow/v1/envelope.proto.
 */

static Cloudflow__V1__EventEnvelope *build_envelope(const formatter_config_t *cfg,
                                                      const cf_packet_item_t *pkt,
                                                      cf_protocol_t protocol,
                                                      const char *event_type,
                                                      cf_stream_id_t stream_id)
{
    Cloudflow__V1__EventEnvelope *e = calloc(1, sizeof(*e));
    char idbuf[CF_EVENT_ID_LEN];

    if (!e)
        return NULL;
    cloudflow__v1__event_envelope__init(e);

    cf_event_id(idbuf, cfg->source_host, cfg->capture_interface,
                pkt->observed_time_unix_nano, pkt->data, pkt->captured_len);

    e->event_id = cfmt_dup_str(idbuf);
    e->schema_version = 1;
    e->source_type = cfmt_dup_str(protocol == CF_PROTO_DHCPV4 ? "dhcpv4" : "dhcpv6");
    e->source_host = cfmt_dup_str(cfg->source_host);
    e->source_instance = cfmt_dup_str(cfg->source_instance);
    e->capture_interface = cfmt_dup_str(cfg->capture_interface);
    e->observation_method = cfmt_dup_str(cfg->observation_method);
    e->observed_time_unix_nano = pkt->observed_time_unix_nano;
    e->ingest_time_unix_nano = cf_now_unix_nano();
    e->event_type = cfmt_dup_str(event_type);
    e->visibility = CLOUDFLOW__V1__VISIBILITY_LEVEL__VISIBILITY_PACKET_PAYLOAD;
    e->confidence = CLOUDFLOW__V1__OBSERVATION_CONFIDENCE__OBSERVATION_CONFIDENCE_OBSERVED;
    e->payload_schema = cfmt_dup_str(protocol == CF_PROTO_DHCPV4 ? "cloudflow.v1.DhcpV4PacketEvent"
                                                                   : "cloudflow.v1.DhcpV6PacketEvent");
    e->stream_name = cfmt_dup_str(cf_stream_name(stream_id));

    if (!e->event_id || !e->source_type || !e->source_host || !e->source_instance ||
        !e->capture_interface || !e->observation_method || !e->event_type ||
        !e->payload_schema || !e->stream_name) {
        cloudflow__v1__event_envelope__free_unpacked(e, NULL);
        return NULL;
    }

    return e;
}

/* ------------------------------------------------------------------------
 * D11 oversize handling: clear raw_dhcp_payload / set raw_payload_truncated
 * on whichever protocol's tree is in play. Both DhcpV4PacketEvent and
 * DhcpV6PacketEvent have identically-typed raw_dhcp_payload
 * (ProtobufCBinaryData) and raw_payload_truncated (protobuf_c_boolean)
 * fields at their own field numbers, but are otherwise unrelated generated
 * structs -- there is no common base to genericize this over, so the
 * caller passes each protocol's own pointer/field pair in explicitly. */

static void clear_raw_payload(ProtobufCBinaryData *raw, protobuf_c_boolean *truncated)
{
    free(raw->data);
    raw->data = NULL;
    raw->len = 0;
    *truncated = 1;
}

/* ------------------------------------------------------------------------
 * cf_format_packet(): the pure function (decap + classify + parse + build
 * envelope + pack) used by both the formatter thread below and tests. */

int cf_format_packet(const formatter_config_t *cfg, const cf_packet_item_t *pkt,
                      cf_event_item_t *item)
{
    cf_decap_udp_t decap;
    cf_protocol_t protocol;
    cf_stream_id_t stream_id;
    const char *event_type = NULL;
    Cloudflow__V1__DhcpV4PacketEvent *v4 = NULL;
    Cloudflow__V1__DhcpV6PacketEvent *v6 = NULL;
    Cloudflow__V1__PacketObservation *pobs;
    Cloudflow__V1__EventEnvelope *envelope;
    Cloudflow__V1__CloudFlowEvent *ev;
    size_t n_warnings = 0;
    size_t packed_size;

    if (!cfg || !pkt || !item)
        return -1;

    if (cf_decap_udp(pkt->data, pkt->captured_len, &decap) != CF_DECAP_OK) {
        if (cfg->stats)
            CF_ATOMIC_INC(cfg->stats->packets_skipped_total);
        return CF_FORMAT_SKIP;
    }

    if (decap.src_port == 67 || decap.src_port == 68 || decap.dst_port == 67 ||
        decap.dst_port == 68) {
        protocol = CF_PROTO_DHCPV4;
        stream_id = CF_STREAM_DHCPV4;
    } else if (decap.src_port == 546 || decap.src_port == 547 || decap.dst_port == 546 ||
               decap.dst_port == 547) {
        protocol = CF_PROTO_DHCPV6;
        stream_id = CF_STREAM_DHCPV6;
    } else {
        if (cfg->stats)
            CF_ATOMIC_INC(cfg->stats->packets_skipped_total);
        return CF_FORMAT_SKIP;
    }

    if (protocol == CF_PROTO_DHCPV4)
        v4 = cf_dhcpv4_parse(decap.payload, decap.payload_len, &event_type);
    else
        v6 = cf_dhcpv6_parse(decap.payload, decap.payload_len, &event_type);

    if (!v4 && !v6) {
        if (cfg->stats)
            CF_ATOMIC_INC(cfg->stats->packets_skipped_total);
        return CF_FORMAT_SKIP;
    }

    pobs = build_packet_observation(pkt, &decap);
    if (!pobs) {
        if (v4)
            cf_dhcpv4_event_free(v4);
        else
            cf_dhcpv6_event_free(v6);
        return -1;
    }

    if (v4)
        v4->packet = pobs;
    else
        v6->packet = pobs;

    envelope = build_envelope(cfg, pkt, protocol, event_type, stream_id);
    if (!envelope) {
        if (v4)
            cf_dhcpv4_event_free(v4);
        else
            cf_dhcpv6_event_free(v6);
        return -1;
    }

    ev = calloc(1, sizeof(*ev));
    if (!ev) {
        cloudflow__v1__event_envelope__free_unpacked(envelope, NULL);
        if (v4)
            cf_dhcpv4_event_free(v4);
        else
            cf_dhcpv6_event_free(v6);
        return -1;
    }
    cloudflow__v1__cloud_flow_event__init(ev);
    ev->envelope = envelope;

    if (v4) {
        ev->payload_case = CLOUDFLOW__V1__CLOUD_FLOW_EVENT__PAYLOAD_DHCPV4_PACKET;
        ev->dhcpv4_packet = v4;
        n_warnings = v4->n_parser_warnings;
    } else {
        ev->payload_case = CLOUDFLOW__V1__CLOUD_FLOW_EVENT__PAYLOAD_DHCPV6_PACKET;
        ev->dhcpv6_packet = v6;
        n_warnings = v6->n_parser_warnings;
    }

    packed_size = cloudflow__v1__cloud_flow_event__get_packed_size(ev);
    if (packed_size > CLOUDFLOW_EVENT_MAX_SIZE) {
        /* D11: drop the raw payload bytes and re-pack once. */
        if (v4)
            clear_raw_payload(&v4->raw_dhcp_payload, &v4->raw_payload_truncated);
        else
            clear_raw_payload(&v6->raw_dhcp_payload, &v6->raw_payload_truncated);

        packed_size = cloudflow__v1__cloud_flow_event__get_packed_size(ev);
    }

    if (packed_size > CLOUDFLOW_EVENT_MAX_SIZE) {
        if (cfg->stats)
            CF_ATOMIC_INC(cfg->stats->events_oversize_dropped_total);
        cloudflow__v1__cloud_flow_event__free_unpacked(ev, NULL);
        return CF_FORMAT_SKIP;
    }

    item->payload_len = (uint32_t)cloudflow__v1__cloud_flow_event__pack(ev, item->payload);
    item->observed_time_unix_nano = pkt->observed_time_unix_nano;
    item->stream_id = stream_id;
    item->protocol = protocol;

    {
        const char *et = event_type ? event_type : "";
        size_t n = strlen(et);

        if (n >= CLOUDFLOW_EVENT_TYPE_MAX)
            n = CLOUDFLOW_EVENT_TYPE_MAX - 1;
        memcpy(item->event_type, et, n);
        item->event_type[n] = '\0';
    }

    cloudflow__v1__cloud_flow_event__free_unpacked(ev, NULL);

    if (cfg->stats) {
        CF_ATOMIC_INC(cfg->stats->events_formatted_total);
        if (protocol == CF_PROTO_DHCPV4)
            CF_ATOMIC_INC(cfg->stats->events_formatted_dhcpv4_total);
        else
            CF_ATOMIC_INC(cfg->stats->events_formatted_dhcpv6_total);
        CF_ATOMIC_ADD(cfg->stats->parse_warnings_total, (unsigned long)n_warnings);
    }

    return 0;
}

/* ------------------------------------------------------------------------
 * formatter_start()/formatter_stop(): the thread wrapper. Polls `in` with a
 * 1ms cf_sleep_ns() backoff when empty (DHCP is low-rate -- see D10 in
 * docs/architecture.md -- so there is no epoll/eventfd wiring here,
 * unlike rx_reader's ring); exits its main loop once cf_stop_notified(), but
 * always drains whatever is still in `in` first so a formatter stopped
 * after its upstream (rx-reader/pcap-replay) has already stopped loses
 * nothing already queued.
 */

#define FORMATTER_POLL_SLEEP_NS (1000L * 1000L) /* 1 ms */

typedef struct {
    formatter_config_t cfg;
    pthread_t thread;
    atomic_bool started;
} cf_formatter_state_t;

static cf_formatter_state_t g_formatter;

static void formatter_process_one(const formatter_config_t *cfg, const cf_packet_item_t *pkt)
{
    cf_event_item_t item;
    int rc;

    memset(&item, 0, sizeof(item));

    rc = cf_format_packet(cfg, pkt, &item);
    if (rc == 0) {
        (void)cf_queue_push_policy(cfg->out, &item, sizeof(item), cfg->on_full,
                                    cfg->stats ? &cfg->stats->formatter_queue_drop_total : NULL);
    } else if (rc < 0) {
        cf_log(CF_LOG_WARN, "cf_format_packet failed (allocation error), packet dropped", NULL);
    }
    /* rc == CF_FORMAT_SKIP: already counted inside cf_format_packet. */

    if (cfg->stats)
        CF_ATOMIC_STORE(cfg->stats->formatter_queue_depth, cf_queue_length(cfg->out));
}

static void formatter_drain(const formatter_config_t *cfg)
{
    cf_packet_item_t pkt;

    while (cf_queue_pop(cfg->in, &pkt) == 0)
        formatter_process_one(cfg, &pkt);
}

static void *formatter_thread_main(void *arg)
{
    cf_formatter_state_t *state = arg;
    cf_packet_item_t pkt;

    pthread_setname_np(pthread_self(), "cf-formatter");

    cf_log(CF_LOG_INFO, "event-formatter started", NULL);

    while (!cf_stop_notified()) {
        if (cf_queue_pop(state->cfg.in, &pkt) == 0)
            formatter_process_one(&state->cfg, &pkt);
        else
            cf_sleep_ns(FORMATTER_POLL_SLEEP_NS);
    }

    /* Lossless shutdown: drain whatever is still queued even though stop
     * has been notified. */
    formatter_drain(&state->cfg);

    cf_log(CF_LOG_INFO, "event-formatter stopped", NULL);

    return NULL;
}

int formatter_start(const formatter_config_t *cfg)
{
    if (!cfg || !cfg->in || !cfg->out || !cfg->stats) {
        cf_log(CF_LOG_ERROR, "formatter_start: invalid config (in/out/stats required)", NULL);
        return -1;
    }

    if (atomic_load(&g_formatter.started)) {
        cf_log(CF_LOG_ERROR, "formatter_start: already started", NULL);
        return -1;
    }

    memset(&g_formatter, 0, sizeof(g_formatter));
    g_formatter.cfg = *cfg;

    if (pthread_create(&g_formatter.thread, NULL, formatter_thread_main, &g_formatter) != 0) {
        cf_log(CF_LOG_ERROR, "formatter_start: pthread_create() failed", NULL);
        return -1;
    }

    atomic_store(&g_formatter.started, true);

    return 0;
}

void formatter_stop(void)
{
    if (!atomic_load(&g_formatter.started))
        return;

    cf_stop_notify(0);
    pthread_join(g_formatter.thread, NULL);

    atomic_store(&g_formatter.started, false);
}
