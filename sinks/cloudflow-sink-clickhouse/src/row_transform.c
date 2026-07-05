#include "row_transform.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "yyjson.h"

#include "cloudflow/v1/dhcp.pb-c.h"
#include "cloudflow/v1/dns.pb-c.h"

/* ---- small helpers (shared shape with the metrics sink transform) -------- */

/* observed_time_unix_nano -> "YYYY-MM-DD HH:MM:SS.fffffffff" (UTC), the string
 * form ClickHouse parses unambiguously into DateTime64(9) with full nanosecond
 * precision. A bare numeric epoch is NOT usable: ClickHouse's JSONEachRow
 * DateTime64 reader rejects the fractional part of a number ("Cannot parse
 * input: expected ',' before: '.000000000'"), which the real-delivery harness
 * caught. The column is DateTime64(9) with no timezone, so ClickHouse reads
 * this string in the server timezone (UTC by default). */
static void format_observed_time(int64_t nanos, char *buf, size_t cap)
{
    int64_t   secs = nanos / 1000000000LL;
    int64_t   frac = nanos % 1000000000LL;
    time_t    t;
    struct tm tmv;

    if (frac < 0) { /* floor toward -inf so sub-second stays in [0,1e9) */
        frac += 1000000000LL;
        secs -= 1;
    }
    t = (time_t)secs;
    gmtime_r(&t, &tmv);
    snprintf(buf, cap, "%04d-%02d-%02d %02d:%02d:%02d.%09lld",
             tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
             tmv.tm_hour, tmv.tm_min, tmv.tm_sec, (long long)frac);
}

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

/* DNS RCODE number -> mnemonic (RFC 1035 + extensions); unknown -> decimal. */
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

/* ---- yyjson row-object helpers ------------------------------------------ */

/* Add a string column, but only when `v` is non-empty: an absent JSONEachRow
 * key lets ClickHouse fill the column DEFAULT. */
static int add_str(yyjson_mut_doc *doc, yyjson_mut_val *row, const char *key, const char *v)
{
    if (!v || !v[0])
        return 0;
    return yyjson_mut_obj_add_strcpy(doc, row, key, v) ? 0 : -1;
}

static int add_uint(yyjson_mut_doc *doc, yyjson_mut_val *row, const char *key, uint64_t v)
{
    return yyjson_mut_obj_add_uint(doc, row, key, v) ? 0 : -1;
}

/* ---- common columns ------------------------------------------------------ */

static int add_common(yyjson_mut_doc *doc, yyjson_mut_val *row,
                      const Cloudflow__V1__EventEnvelope *env,
                      const Cloudflow__V1__PacketObservation *pkt)
{
    char time_buf[48];

    if (add_str(doc, row, "event_id", env->event_id) != 0)
        return -1;

    format_observed_time(env->observed_time_unix_nano, time_buf, sizeof(time_buf));
    /* observed_time is a quoted datetime string for DateTime64(9). */
    if (add_str(doc, row, "observed_time", time_buf) != 0)
        return -1;

    if (add_str(doc, row, "source_type", env->source_type) != 0 ||
        add_str(doc, row, "source_host", env->source_host) != 0 ||
        add_str(doc, row, "capture_interface", env->capture_interface) != 0 ||
        add_str(doc, row, "event_type", env->event_type) != 0)
        return -1;

    if (pkt) {
        if (pkt->network &&
            (add_str(doc, row, "src_ip", pkt->network->src_ip) != 0 ||
             add_str(doc, row, "dst_ip", pkt->network->dst_ip) != 0))
            return -1;
        if (pkt->link && add_str(doc, row, "src_mac", pkt->link->src_mac) != 0)
            return -1;
    }
    return 0;
}

/* ---- per-protocol columns ----------------------------------------------- */

static int add_dhcpv4(yyjson_mut_doc *doc, yyjson_mut_val *row,
                      const Cloudflow__V1__DhcpV4PacketEvent *p)
{
    const Cloudflow__V1__DhcpV4Interpretation *in = p ? p->interpretation : NULL;
    const Cloudflow__V1__DhcpV4DecodedOptions *dec = p ? p->decoded : NULL;

    if (add_str(doc, row, "message_type", dhcpv4_msgtype_name(dec)) != 0)
        return -1;
    if (in) {
        if (add_str(doc, row, "client_key", in->normalized_client_key) != 0 ||
            add_str(doc, row, "assigned_address", in->lease_address) != 0)
            return -1;
    }
    if (dec && add_str(doc, row, "requested_address", dec->requested_ip_address) != 0)
        return -1;
    return add_uint(doc, row, "is_relayed", (in && in->is_relayed) ? 1 : 0);
}

static int add_dhcpv6(yyjson_mut_doc *doc, yyjson_mut_val *row,
                      const Cloudflow__V1__DhcpV6PacketEvent *p)
{
    Cloudflow__V1__DhcpV6Header__MessageType t =
        (p && p->header) ? p->header->message_type
                         : CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__MESSAGE_TYPE_UNSPECIFIED;
    int relayed = (t == CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__RELAY_FORW ||
                   t == CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__RELAY_REPL);

    if (add_str(doc, row, "message_type", dhcpv6_msgtype_name(t)) != 0)
        return -1;
    if (p && p->decoded) {
        const Cloudflow__V1__DhcpV6DecodedOptions *dec = p->decoded;
        if (dec->client_duid.len > 0) {
            char duid_hex[264];
            hex_encode(dec->client_duid.data, dec->client_duid.len, duid_hex, sizeof(duid_hex));
            if (add_str(doc, row, "client_key", duid_hex) != 0)
                return -1;
        }
        if (dec->n_assigned_addresses > 0 && dec->assigned_addresses[0] &&
            add_str(doc, row, "assigned_address", dec->assigned_addresses[0]) != 0)
            return -1;
    }
    return add_uint(doc, row, "is_relayed", relayed ? 1 : 0);
}

static int add_dns(yyjson_mut_doc *doc, yyjson_mut_val *row,
                   const Cloudflow__V1__DnsTransactionEvent *tx)
{
    char rcode_buf[16];

    if (tx->query && tx->query->n_questions > 0 && tx->query->questions[0]) {
        const Cloudflow__V1__DnsQuestion *q = tx->query->questions[0];
        char qtype_buf[16];
        const char *qtype;

        if (add_str(doc, row, "qname", q->qname) != 0)
            return -1;
        if (q->qtype_name && q->qtype_name[0]) {
            qtype = q->qtype_name;
        } else {
            snprintf(qtype_buf, sizeof(qtype_buf), "%u", q->qtype);
            qtype = qtype_buf;
        }
        if (add_str(doc, row, "qtype", qtype) != 0)
            return -1;
        if (add_uint(doc, row, "qclass", q->qclass) != 0)
            return -1;
    }

    if (tx->response && tx->response->header &&
        add_str(doc, row, "rcode",
                dns_rcode_name(tx->response->header->rcode, rcode_buf, sizeof(rcode_buf))) != 0)
        return -1;

    if (tx->rtt_valid) {
        double seconds = (double)tx->rtt_nanos / 1e9;
        if (!yyjson_mut_obj_add_real(doc, row, "rtt_seconds", seconds))
            return -1;
    }
    if (add_uint(doc, row, "rtt_valid", tx->rtt_valid ? 1 : 0) != 0)
        return -1;

    /* role and service_role are stable DNS identity columns: always emitted
     * for a DNS row (service_role as "" when the operator mapped none), so the
     * column is a dependable, present key rather than sometimes-absent. */
    if (!yyjson_mut_obj_add_strcpy(doc, row, "role", dns_leg_name(tx->role)))
        return -1;
    if (!yyjson_mut_obj_add_strcpy(doc, row, "service_role",
                                   tx->service_role ? tx->service_role : ""))
        return -1;
    if (add_str(doc, row, "client_ip", tx->client_ip) != 0 ||
        add_str(doc, row, "server_ip", tx->server_ip) != 0)
        return -1;
    return 0;
}

/* ---- transform entry point ---------------------------------------------- */

int cf_row_transform(void *user, const Cloudflow__V1__CloudFlowEvent *ev,
                     const char *source_stream, cf_sink_buf_t *out)
{
    const Cloudflow__V1__EventEnvelope *env = ev ? ev->envelope : NULL;
    const Cloudflow__V1__PacketObservation *pkt = NULL;
    yyjson_mut_doc *doc;
    yyjson_mut_val *row;
    char *json = NULL;
    int rc = -1;

    (void)user;
    (void)source_stream;

    if (!ev || !env)
        return -1; /* malformed -> dead-letter */

    doc = yyjson_mut_doc_new(NULL);
    if (!doc)
        return -1;
    row = yyjson_mut_obj(doc);
    if (!row)
        goto done;

    switch (ev->payload_case) {
    case CLOUDFLOW__V1__CLOUD_FLOW_EVENT__PAYLOAD_DHCPV4_PACKET:
        if (!ev->dhcpv4_packet)
            goto done;
        pkt = ev->dhcpv4_packet->packet;
        break;
    case CLOUDFLOW__V1__CLOUD_FLOW_EVENT__PAYLOAD_DHCPV6_PACKET:
        if (!ev->dhcpv6_packet)
            goto done;
        pkt = ev->dhcpv6_packet->packet;
        break;
    case CLOUDFLOW__V1__CLOUD_FLOW_EVENT__PAYLOAD_DNS_TRANSACTION:
        if (!ev->dns_transaction)
            goto done;
        pkt = ev->dns_transaction->query_packet ? ev->dns_transaction->query_packet
                                                : ev->dns_transaction->response_packet;
        break;
    default:
        goto done; /* unset / unknown payload -> dead-letter */
    }

    if (add_common(doc, row, env, pkt) != 0)
        goto done;

    switch (ev->payload_case) {
    case CLOUDFLOW__V1__CLOUD_FLOW_EVENT__PAYLOAD_DHCPV4_PACKET:
        if (add_dhcpv4(doc, row, ev->dhcpv4_packet) != 0)
            goto done;
        break;
    case CLOUDFLOW__V1__CLOUD_FLOW_EVENT__PAYLOAD_DHCPV6_PACKET:
        if (add_dhcpv6(doc, row, ev->dhcpv6_packet) != 0)
            goto done;
        break;
    case CLOUDFLOW__V1__CLOUD_FLOW_EVENT__PAYLOAD_DNS_TRANSACTION:
        if (add_dns(doc, row, ev->dns_transaction) != 0)
            goto done;
        break;
    default:
        goto done;
    }

    yyjson_mut_doc_set_root(doc, row);
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
