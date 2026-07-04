#include "metrics_transform.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "yyjson.h"

#include "cloudflow/v1/dhcp.pb-c.h"
#include "cloudflow/v1/dns.pb-c.h"

/* ---- small helpers ------------------------------------------------------ */

/* Render observed_time_unix_nano as seconds with exactly 9 decimal places
 * (identical rule to the event sink, docs/splunk-metrics.md "Metric-point
 * format": time is the observed wire moment). */
static void format_metric_time(int64_t nanos, char *buf, size_t cap)
{
    const char *sign = "";
    uint64_t mag, secs, frac;

    if (nanos < 0) {
        sign = "-";
        mag = (uint64_t)(-(nanos + 1)) + 1u; /* safe negation for INT64_MIN */
    } else {
        mag = (uint64_t)nanos;
    }
    secs = mag / 1000000000ull;
    frac = mag % 1000000000ull;
    snprintf(buf, cap, "%s%" PRIu64 ".%09" PRIu64, sign, secs, frac);
}

/* Leg role -> normalized dimension value (docs/event-model.md). */
static const char *dns_leg_name(Cloudflow__V1__DnsLeg role)
{
    switch (role) {
    case CLOUDFLOW__V1__DNS_LEG__DNS_LEG_CLIENT_FACING:
        return "client_facing";
    case CLOUDFLOW__V1__DNS_LEG__DNS_LEG_BACKEND:
        return "backend";
    case CLOUDFLOW__V1__DNS_LEG__DNS_LEG_RECURSION_UPSTREAM:
        return "recursion_upstream";
    case CLOUDFLOW__V1__DNS_LEG__DNS_LEG_UNKNOWN:
        return "unknown";
    case CLOUDFLOW__V1__DNS_LEG__DNS_LEG_UNSPECIFIED:
    default:
        return "unspecified";
    }
}

/* DNS RCODE number -> mnemonic (RFC 1035 + extensions). Unknown codes fall
 * back to their decimal value written into `buf`. */
static const char *dns_rcode_name(uint32_t rcode, char *buf, size_t cap)
{
    switch (rcode) {
    case 0:
        return "NOERROR";
    case 1:
        return "FORMERR";
    case 2:
        return "SERVFAIL";
    case 3:
        return "NXDOMAIN";
    case 4:
        return "NOTIMP";
    case 5:
        return "REFUSED";
    case 6:
        return "YXDOMAIN";
    case 7:
        return "YXRRSET";
    case 8:
        return "NXRRSET";
    case 9:
        return "NOTAUTH";
    case 10:
        return "NOTZONE";
    case 16:
        return "BADVERS";
    default:
        snprintf(buf, cap, "%u", rcode);
        return buf;
    }
}

static const char *dhcpv4_msgtype_name(const Cloudflow__V1__DhcpV4DecodedOptions *decoded)
{
    if (decoded && decoded->message_type_name && decoded->message_type_name[0])
        return decoded->message_type_name;
    switch (decoded ? decoded->message_type
                    : CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__MESSAGE_TYPE_UNSPECIFIED) {
    case CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__DISCOVER:
        return "DISCOVER";
    case CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__OFFER:
        return "OFFER";
    case CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__REQUEST:
        return "REQUEST";
    case CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__DECLINE:
        return "DECLINE";
    case CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__ACK:
        return "ACK";
    case CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__NAK:
        return "NAK";
    case CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__RELEASE:
        return "RELEASE";
    case CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__INFORM:
        return "INFORM";
    case CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__FORCERENEW:
        return "FORCERENEW";
    case CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__LEASEQUERY:
        return "LEASEQUERY";
    case CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__LEASEUNASSIGNED:
        return "LEASEUNASSIGNED";
    case CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__LEASEUNKNOWN:
        return "LEASEUNKNOWN";
    case CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__LEASEACTIVE:
        return "LEASEACTIVE";
    default:
        return "UNSPECIFIED";
    }
}

static const char *dhcpv6_msgtype_name(Cloudflow__V1__DhcpV6Header__MessageType t)
{
    switch (t) {
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__SOLICIT:
        return "SOLICIT";
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__ADVERTISE:
        return "ADVERTISE";
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__REQUEST:
        return "REQUEST";
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__CONFIRM:
        return "CONFIRM";
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__RENEW:
        return "RENEW";
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__REBIND:
        return "REBIND";
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__REPLY:
        return "REPLY";
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__RELEASE:
        return "RELEASE";
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__DECLINE:
        return "DECLINE";
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__RECONFIGURE:
        return "RECONFIGURE";
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__INFORMATION_REQUEST:
        return "INFORMATION_REQUEST";
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__RELAY_FORW:
        return "RELAY_FORW";
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__RELAY_REPL:
        return "RELAY_REPL";
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__LEASEQUERY:
        return "LEASEQUERY";
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__LEASEQUERY_REPLY:
        return "LEASEQUERY_REPLY";
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__LEASEQUERY_DONE:
        return "LEASEQUERY_DONE";
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__LEASEQUERY_DATA:
        return "LEASEQUERY_DATA";
    default:
        return "UNSPECIFIED";
    }
}

static void hex_encode(const uint8_t *data, size_t len, char *buf, size_t cap)
{
    static const char hexd[] = "0123456789abcdef";
    size_t o = 0;
    if (cap == 0)
        return;
    for (size_t i = 0; i < len && o + 2 < cap; i++) {
        buf[o++] = hexd[(data[i] >> 4) & 0xf];
        buf[o++] = hexd[data[i] & 0xf];
    }
    buf[o] = '\0';
}

/* ---- metric-point emission ---------------------------------------------- */

typedef struct {
    const char *key;
    const char *val;
} dim_t;

typedef struct {
    const char *source;
    const char *host;
    const char *index; /* may be "" -> omitted */
    const char *time_str;
} point_meta_t;

static int dim_cmp(const void *a, const void *b)
{
    return strcmp(((const dim_t *)a)->key, ((const dim_t *)b)->key);
}

/* Append one metric-point object (+'\n') to `out`. `value_is_int` selects the
 * numeric encoding (counts are integers, rtt_seconds is a real). Dimensions
 * with a NULL value are skipped; the rest are emitted in sorted-key order for
 * stable goldens (structural compare ignores order regardless). Returns 0 on
 * success, -1 on OOM. */
static int append_point(cf_sink_buf_t *out, const point_meta_t *m, const char *metric_name,
                        int value_is_int, double real_val, uint64_t int_val, dim_t *dims,
                        size_t ndims)
{
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root, *fields, *mval;
    char keybuf[96];
    char *json = NULL;
    int rc = -1;

    if (!doc)
        return -1;

    root = yyjson_mut_obj(doc);
    fields = yyjson_mut_obj(doc);
    if (!root || !fields)
        goto done;

    snprintf(keybuf, sizeof(keybuf), "metric_name:%s", metric_name);
    mval = value_is_int ? yyjson_mut_uint(doc, int_val) : yyjson_mut_real(doc, real_val);
    if (!mval)
        goto done;
    if (!yyjson_mut_obj_add_val(doc, fields, keybuf, mval))
        goto done;

    qsort(dims, ndims, sizeof(*dims), dim_cmp);
    for (size_t i = 0; i < ndims; i++) {
        if (!dims[i].val)
            continue;
        if (!yyjson_mut_obj_add_strcpy(doc, fields, dims[i].key, dims[i].val))
            goto done;
    }

    /* Sorted top-level keys: fields, host, index, source, sourcetype, time. */
    yyjson_mut_obj_add_val(doc, root, "fields", fields);
    yyjson_mut_obj_add_strcpy(doc, root, "host", m->host ? m->host : "");
    if (m->index && m->index[0])
        yyjson_mut_obj_add_strcpy(doc, root, "index", m->index);
    yyjson_mut_obj_add_strcpy(doc, root, "source", m->source ? m->source : "");
    yyjson_mut_obj_add_strcpy(doc, root, "sourcetype", "cloudflow:metric");
    yyjson_mut_obj_add_val(doc, root, "time", yyjson_mut_rawcpy(doc, m->time_str));

    yyjson_mut_doc_set_root(doc, root);
    json = yyjson_mut_write(doc, YYJSON_WRITE_NOFLAG, NULL);
    if (!json)
        goto done;

    if (out->len > 0 && cf_sink_buf_append(out, "\n", 1) != 0)
        goto done;
    if (cf_sink_buf_append(out, json, strlen(json)) != 0)
        goto done;
    rc = 0;

done:
    free(json);
    yyjson_mut_doc_free(doc);
    return rc;
}

/* ---- per-protocol mapping ----------------------------------------------- */

static int emit_dns(const cf_config_t *cfg, const Cloudflow__V1__DnsTransactionEvent *tx,
                    const char *event_type, const point_meta_t *m, cf_sink_buf_t *out)
{
    const char *role = dns_leg_name(tx->role);
    const char *service_role = (tx->service_role && tx->service_role[0]) ? tx->service_role : NULL;

    if (strcmp(event_type, "dns.query.unanswered") == 0) {
        dim_t dims[2];
        size_t n = 0;
        dims[n++] = (dim_t){"cf_role", role};
        dims[n++] = (dim_t){"cf_service_role", service_role};
        if (cf_metrics_enabled(cfg, CF_METRIC_DNS_UNANSWERED_TOTAL))
            return append_point(out, m, CF_METRIC_DNS_UNANSWERED_TOTAL, 1, 0.0, 1, dims, n);
        return 0;
    }
    if (strcmp(event_type, "dns.response.unmatched") == 0) {
        dim_t dims[2];
        size_t n = 0;
        dims[n++] = (dim_t){"cf_role", role};
        dims[n++] = (dim_t){"cf_service_role", service_role};
        if (cf_metrics_enabled(cfg, CF_METRIC_DNS_UNMATCHED_TOTAL))
            return append_point(out, m, CF_METRIC_DNS_UNMATCHED_TOTAL, 1, 0.0, 1, dims, n);
        return 0;
    }

    /* dns.transaction.observed (default DNS mapping). */
    {
        char rcode_buf[16];
        char qtype_buf[16];
        const char *rcode = NULL, *qtype = NULL, *server_ip = NULL;
        dim_t dims[5];
        size_t n = 0;

        if (tx->response && tx->response->header)
            rcode = dns_rcode_name(tx->response->header->rcode, rcode_buf, sizeof(rcode_buf));

        if (cfg->dim_dns_qtype) {
            if (tx->query && tx->query->n_questions > 0 && tx->query->questions[0]) {
                const Cloudflow__V1__DnsQuestion *q = tx->query->questions[0];
                if (q->qtype_name && q->qtype_name[0]) {
                    qtype = q->qtype_name;
                } else {
                    snprintf(qtype_buf, sizeof(qtype_buf), "%u", q->qtype);
                    qtype = qtype_buf;
                }
            }
        }
        if (cfg->dim_dns_server_ip && tx->server_ip && tx->server_ip[0])
            server_ip = tx->server_ip;

        dims[n++] = (dim_t){"cf_role", role};
        dims[n++] = (dim_t){"cf_service_role", service_role};
        dims[n++] = (dim_t){"cf_rcode", rcode};
        dims[n++] = (dim_t){"cf_qtype", qtype};
        dims[n++] = (dim_t){"cf_server_ip", server_ip};

        if (cf_metrics_enabled(cfg, CF_METRIC_DNS_TRANSACTIONS_TOTAL)) {
            if (append_point(out, m, CF_METRIC_DNS_TRANSACTIONS_TOTAL, 1, 0.0, 1, dims, n) != 0)
                return -1;
        }
        if (tx->rtt_valid && cf_metrics_enabled(cfg, CF_METRIC_DNS_RTT_SECONDS)) {
            double seconds = (double)tx->rtt_nanos / 1e9;
            if (append_point(out, m, CF_METRIC_DNS_RTT_SECONDS, 0, seconds, 0, dims, n) != 0)
                return -1;
        }
        return 0;
    }
}

static int emit_dhcp(const cf_config_t *cfg, const Cloudflow__V1__CloudFlowEvent *ev,
                     const char *source_type, const point_meta_t *m, cf_sink_buf_t *out)
{
    const char *msg_type;
    const char *relayed;
    const char *client_key = NULL;
    char duid_hex[264];
    dim_t dims[4];
    size_t n = 0;

    if (ev->payload_case == CLOUDFLOW__V1__CLOUD_FLOW_EVENT__PAYLOAD_DHCPV4_PACKET) {
        const Cloudflow__V1__DhcpV4PacketEvent *p = ev->dhcpv4_packet;
        msg_type = dhcpv4_msgtype_name(p ? p->decoded : NULL);
        relayed = (p && p->interpretation && p->interpretation->is_relayed) ? "true" : "false";
        if (cfg->dim_dhcp_client_key && p && p->interpretation &&
            p->interpretation->normalized_client_key &&
            p->interpretation->normalized_client_key[0])
            client_key = p->interpretation->normalized_client_key;
    } else {
        const Cloudflow__V1__DhcpV6PacketEvent *p = ev->dhcpv6_packet;
        Cloudflow__V1__DhcpV6Header__MessageType t =
            (p && p->header) ? p->header->message_type
                             : CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__MESSAGE_TYPE_UNSPECIFIED;
        msg_type = dhcpv6_msgtype_name(t);
        relayed = (t == CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__RELAY_FORW ||
                   t == CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__RELAY_REPL)
                      ? "true"
                      : "false";
        if (cfg->dim_dhcp_client_key && p && p->decoded && p->decoded->client_duid.len > 0) {
            hex_encode(p->decoded->client_duid.data, p->decoded->client_duid.len, duid_hex,
                       sizeof(duid_hex));
            client_key = duid_hex;
        }
    }

    dims[n++] = (dim_t){"source_type", source_type};
    dims[n++] = (dim_t){"cf_message_type", msg_type};
    dims[n++] = (dim_t){"cf_is_relayed", relayed};
    dims[n++] = (dim_t){"cf_client_key", client_key};

    if (cf_metrics_enabled(cfg, CF_METRIC_DHCP_EVENTS_TOTAL))
        return append_point(out, m, CF_METRIC_DHCP_EVENTS_TOTAL, 1, 0.0, 1, dims, n);
    return 0;
}

/* ---- transform entry point ---------------------------------------------- */

int cf_metrics_transform(void *user, const Cloudflow__V1__CloudFlowEvent *ev,
                         const char *source_stream, cf_sink_buf_t *out)
{
    const cf_config_t *cfg = user;
    const Cloudflow__V1__EventEnvelope *env = ev ? ev->envelope : NULL;
    point_meta_t m;
    char time_buf[48];
    const char *event_type;
    const char *source_type;

    if (!ev || !env)
        return -1; /* malformed -> dead-letter */

    format_metric_time(env->observed_time_unix_nano, time_buf, sizeof(time_buf));
    m.source = (env->stream_name && env->stream_name[0]) ? env->stream_name
                                                         : (source_stream ? source_stream : "");
    m.host = env->source_host ? env->source_host : "";
    m.index = cfg->metrics_index ? cfg->metrics_index : "";
    m.time_str = time_buf;

    event_type = env->event_type ? env->event_type : "";
    source_type = env->source_type ? env->source_type : "";

    switch (ev->payload_case) {
    case CLOUDFLOW__V1__CLOUD_FLOW_EVENT__PAYLOAD_DNS_TRANSACTION:
        if (!ev->dns_transaction)
            return -1;
        return emit_dns(cfg, ev->dns_transaction, event_type, &m, out);
    case CLOUDFLOW__V1__CLOUD_FLOW_EVENT__PAYLOAD_DHCPV4_PACKET:
        if (!ev->dhcpv4_packet)
            return -1;
        return emit_dhcp(cfg, ev, source_type[0] ? source_type : "dhcpv4", &m, out);
    case CLOUDFLOW__V1__CLOUD_FLOW_EVENT__PAYLOAD_DHCPV6_PACKET:
        if (!ev->dhcpv6_packet)
            return -1;
        return emit_dhcp(cfg, ev, source_type[0] ? source_type : "dhcpv6", &m, out);
    case CLOUDFLOW__V1__CLOUD_FLOW_EVENT__PAYLOAD_DHCPV4_LEASE:
        /* A known-but-metric-less payload (reserved, docs/event-model.md): a
         * valid event that maps to no metric -- success, no output. */
        return 0;
    default:
        return -1; /* unset / unknown payload -> dead-letter */
    }
}
