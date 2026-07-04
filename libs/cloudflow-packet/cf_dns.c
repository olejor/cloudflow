/* WP-DNS03 DNS message parser: 12-byte header, question section, the three
 * resource-record sections (answers/authority/additional), EDNS0 OPT
 * pseudo-record extraction, and best-effort RDATA text for the common record
 * types. Builds a Cloudflow__V1__DnsMessage tree (see dns.proto) using the
 * shared cf_parse_util helpers for all bounded reads, string/bytes building,
 * and the parser-warning list.
 *
 * Security posture (WP-DNS09 will fuzz this): never trusts a length or a
 * pointer. Every field read is checked against msg_len before use; name
 * decompression rejects forward/self pointers, bounds the number of pointer
 * jumps and the total name length, and can never loop or read outside
 * [msg, msg+msg_len). Any structural inconsistency emits a cf_warn() with a
 * useful field_path and yields the best partial message -- as long as the
 * 12-byte header parsed, cf_dns_parse returns 1.
 */

#include "cf_dns.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cf_ipfmt.h"

/* ---- fixed sizes / limits ------------------------------------------------ */

#define DNS_HEADER_LEN 12

/* Name decompression hard limits. A DNS name is at most 255 octets on the
 * wire (RFC 1035 3.1); we also cap the number of compression-pointer jumps so
 * a crafted chain can never spin, independent of the length cap. */
#define DNS_MAX_NAME_OCTETS   255
#define DNS_MAX_LABEL_LEN     63
#define DNS_MAX_POINTER_JUMPS 128

/* Presentation buffer: at most DNS_MAX_NAME_OCTETS printable chars plus NUL.
 * We do not escape special characters (best-effort presentation), so output
 * length is bounded by the octet cap. */
#define DNS_NAME_BUF 512

/* Well-known RR / QTYPE codes. */
#define DNS_TYPE_A     1
#define DNS_TYPE_NS    2
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_SOA   6
#define DNS_TYPE_PTR   12
#define DNS_TYPE_MX    15
#define DNS_TYPE_TXT   16
#define DNS_TYPE_AAAA  28
#define DNS_TYPE_SRV   33
#define DNS_TYPE_OPT   41

/* ---- type-name mapping --------------------------------------------------- */

/* Returns a stable name for a well-known RR type, or writes "TYPE<n>" into
 * `scratch` (>= 16 bytes) and returns it for an unknown type. */
static const char *dns_type_name(uint32_t t, char *scratch, size_t scratch_len)
{
    switch (t) {
    case DNS_TYPE_A:     return "A";
    case DNS_TYPE_NS:    return "NS";
    case DNS_TYPE_CNAME: return "CNAME";
    case DNS_TYPE_SOA:   return "SOA";
    case DNS_TYPE_PTR:   return "PTR";
    case 13:             return "HINFO";
    case DNS_TYPE_MX:    return "MX";
    case DNS_TYPE_TXT:   return "TXT";
    case 17:             return "RP";
    case 24:             return "SIG";
    case 25:             return "KEY";
    case DNS_TYPE_AAAA:  return "AAAA";
    case 29:             return "LOC";
    case DNS_TYPE_SRV:   return "SRV";
    case 35:             return "NAPTR";
    case 39:             return "DNAME";
    case DNS_TYPE_OPT:   return "OPT";
    case 43:             return "DS";
    case 46:             return "RRSIG";
    case 47:             return "NSEC";
    case 48:             return "DNSKEY";
    case 50:             return "NSEC3";
    case 51:             return "NSEC3PARAM";
    case 52:             return "TLSA";
    case 59:             return "CDS";
    case 60:             return "CDNSKEY";
    case 64:             return "SVCB";
    case 65:             return "HTTPS";
    case 252:            return "AXFR";
    case 255:            return "ANY";
    case 257:            return "CAA";
    default:
        snprintf(scratch, scratch_len, "TYPE%u", t);
        return scratch;
    }
}

/* ---- name decompression -------------------------------------------------- */

/* Decodes the DNS name that starts at offset `start` in msg[0..msg_len),
 * writing its presentation form into `out` (dot-separated labels, NO trailing
 * dot; the root name is the empty string ""). ASCII A-Z are lowercased when
 * `lowercase` is non-zero. `*consumed` is set to how many bytes the name
 * occupies *at `start`* -- i.e. how far the parse cursor should advance -- so
 * a name that ends in a compression pointer consumes only up to and including
 * that 2-byte pointer, never the bytes it jumps to.
 *
 * Returns 1 on a clean decode, 0 on any malformation (bad/forward/self
 * pointer, pointer-jump or name-length limit exceeded, reserved label type,
 * or a read past msg_len). On malformation `out` still holds the best partial
 * presentation and `*consumed` is a safe non-negative advance. In every case --
 * success or failure -- `out` is left NUL-terminated, so callers may treat it as
 * a C string regardless of the return value.
 */
static int decode_name(const uint8_t *msg, size_t msg_len, size_t start,
                       int lowercase, char out[DNS_NAME_BUF], size_t *consumed)
{
    size_t pos = start;
    size_t out_len = 0;
    size_t name_octets = 0;
    unsigned jumps = 0;
    int first_ptr_seen = 0;
    int first_label = 1;

    out[0] = '\0';
    *consumed = 0;

    for (;;) {
        uint8_t label_len;

        if (pos >= msg_len)
            goto fail; /* ran off the end of the buffer */

        label_len = msg[pos];

        if ((label_len & 0xc0) == 0x00) {
            /* Normal label (top two bits clear -> length <= 63). */
            if (label_len == 0) {
                /* Root / terminating zero. */
                pos++;
                if (!first_ptr_seen)
                    *consumed = pos - start;
                out[out_len] = '\0';
                return 1;
            }

            if (pos + 1 + label_len > msg_len)
                goto fail; /* label body runs past the buffer */

            /* Each label costs its length octet + its bytes toward the
             * RFC 1035 255-octet name cap. */
            name_octets += (size_t)label_len + 1;
            if (name_octets > DNS_MAX_NAME_OCTETS)
                goto fail;

            if (!first_label && out_len + 1 < DNS_NAME_BUF)
                out[out_len++] = '.';
            first_label = 0;

            for (size_t i = 0; i < label_len && out_len + 1 < DNS_NAME_BUF; i++) {
                uint8_t c = msg[pos + 1 + i];
                if (lowercase && c >= 'A' && c <= 'Z')
                    c = (uint8_t)(c + 0x20);
                out[out_len++] = (char)c;
            }

            pos += (size_t)1 + label_len;
            continue;
        }

        if ((label_len & 0xc0) == 0xc0) {
            /* Compression pointer: 14-bit offset. */
            size_t target;

            if (pos + 2 > msg_len)
                goto fail; /* pointer's second byte is missing */

            target = ((size_t)(label_len & 0x3f) << 8) | (size_t)msg[pos + 1];

            if (!first_ptr_seen) {
                first_ptr_seen = 1;
                *consumed = (pos + 2) - start;
            }

            /* Must point strictly backward -- to an offset earlier than the
             * pointer itself. Rejects self- and forward-pointers outright;
             * the jump cap below catches any residual bounce. */
            if (target >= pos)
                goto fail;

            if (++jumps > DNS_MAX_POINTER_JUMPS)
                goto fail;

            pos = target;
            continue;
        }

        /* 0x40 / 0x80: reserved label types (RFC 6891 deprecated 0x41). */
        goto fail;
    }

fail:
    /* Malformation: keep the doc contract that `out` still holds the best
     * partial presentation as a valid C string. Every label/dot write above is
     * guarded by `out_len + 1 < DNS_NAME_BUF`, so out_len <= DNS_NAME_BUF-1
     * here; clamp defensively regardless so the terminator write is always in
     * bounds. `*consumed` retains whatever safe advance was already set. */
    if (out_len >= DNS_NAME_BUF)
        out_len = DNS_NAME_BUF - 1;
    out[out_len] = '\0';
    return 0;
}

/* ---- RDATA text decoders ------------------------------------------------- */

/* Formats a name-only RDATA (CNAME/NS/PTR) at absolute offset `off`. Returns
 * an owned/sentinel string; sets *malformed on a bad name. */
static char *rdata_name_text(const uint8_t *msg, size_t msg_len, size_t off,
                             int *malformed)
{
    char name[DNS_NAME_BUF];
    size_t consumed;

    if (!decode_name(msg, msg_len, off, 1, name, &consumed))
        *malformed = 1;
    return cf_dup_str(name);
}

/* MX: 16-bit preference + exchange name -> "<pref> <exchange>". */
static char *rdata_mx_text(const uint8_t *msg, size_t msg_len, size_t off,
                           size_t rdlen, int *malformed)
{
    uint16_t pref;
    char name[DNS_NAME_BUF];
    size_t consumed;
    char buf[DNS_NAME_BUF + 16];

    if (rdlen < 3 || !cf_get_be16(msg, msg_len, off, &pref)) {
        *malformed = 1;
        return (char *)protobuf_c_empty_string;
    }
    if (!decode_name(msg, msg_len, off + 2, 1, name, &consumed))
        *malformed = 1;
    snprintf(buf, sizeof(buf), "%u %s", pref, name);
    return cf_dup_str(buf);
}

/* SRV: priority, weight, port (each 16-bit) + target name. */
static char *rdata_srv_text(const uint8_t *msg, size_t msg_len, size_t off,
                            size_t rdlen, int *malformed)
{
    uint16_t prio, weight, port;
    char name[DNS_NAME_BUF];
    size_t consumed;
    char buf[DNS_NAME_BUF + 32];

    if (rdlen < 7 ||
        !cf_get_be16(msg, msg_len, off, &prio) ||
        !cf_get_be16(msg, msg_len, off + 2, &weight) ||
        !cf_get_be16(msg, msg_len, off + 4, &port)) {
        *malformed = 1;
        return (char *)protobuf_c_empty_string;
    }
    if (!decode_name(msg, msg_len, off + 6, 1, name, &consumed))
        *malformed = 1;
    snprintf(buf, sizeof(buf), "%u %u %u %s", prio, weight, port, name);
    return cf_dup_str(buf);
}

/* SOA: mname, rname, then serial/refresh/retry/expire/minimum (5x 32-bit). */
static char *rdata_soa_text(const uint8_t *msg, size_t msg_len, size_t off,
                            size_t rdlen, int *malformed)
{
    char mname[DNS_NAME_BUF];
    char rname[DNS_NAME_BUF];
    size_t consumed;
    size_t p = off;
    size_t rdata_end = off + rdlen;
    uint32_t serial, refresh, retry, expire, minimum;
    char buf[2 * DNS_NAME_BUF + 96];

    if (!decode_name(msg, msg_len, p, 1, mname, &consumed)) {
        *malformed = 1;
        return cf_dup_str(mname);
    }
    p += consumed;
    if (!decode_name(msg, msg_len, p, 1, rname, &consumed)) {
        *malformed = 1;
        return cf_dup_str(rname);
    }
    p += consumed;

    /* The five 32-bit fields must sit inside this record's RDATA. */
    if (p + 20 > rdata_end || p + 20 > msg_len ||
        !cf_get_be32(msg, msg_len, p, &serial) ||
        !cf_get_be32(msg, msg_len, p + 4, &refresh) ||
        !cf_get_be32(msg, msg_len, p + 8, &retry) ||
        !cf_get_be32(msg, msg_len, p + 12, &expire) ||
        !cf_get_be32(msg, msg_len, p + 16, &minimum)) {
        *malformed = 1;
        return (char *)protobuf_c_empty_string;
    }

    snprintf(buf, sizeof(buf), "%s %s %u %u %u %u %u", mname, rname,
             serial, refresh, retry, expire, minimum);
    return cf_dup_str(buf);
}

/* TXT: one or more <length octet><that many bytes> character-strings.
 * Best-effort: concatenate each string's bytes, space-separated. */
static char *rdata_txt_text(const uint8_t *msg, size_t msg_len, size_t off,
                            size_t rdlen, int *malformed)
{
    size_t p = off;
    size_t end = off + rdlen;
    char *buf;
    size_t buf_len = 0;
    int first = 1;

    if (end > msg_len) {
        *malformed = 1;
        end = msg_len;
    }
    if (p >= end)
        return (char *)protobuf_c_empty_string;

    /* rdlen bytes of character-strings decode to at most rdlen chars of text
     * plus separators; rdlen+1 is a safe upper bound for the buffer. */
    buf = malloc(rdlen + 1);
    if (!buf)
        return (char *)protobuf_c_empty_string;

    while (p < end) {
        uint8_t slen = msg[p];
        p++;
        if (p + slen > end) {
            *malformed = 1;
            slen = (uint8_t)(end - p);
        }
        if (!first && buf_len < rdlen)
            buf[buf_len++] = ' ';
        first = 0;
        for (uint8_t i = 0; i < slen && buf_len < rdlen; i++)
            buf[buf_len++] = (char)msg[p + i];
        p += slen;
    }
    buf[buf_len] = '\0';

    if (buf_len == 0) {
        free(buf);
        return (char *)protobuf_c_empty_string;
    }
    return buf;
}

/* Builds RR.rdata_text for the record types CloudFlow decodes; leaves the
 * empty-string sentinel for everything else. `off`/`rdlen` describe the RDATA
 * within the whole message (names may compress back into it). Sets
 * *malformed when the RDATA does not decode cleanly. */
static char *rdata_text_for(const uint8_t *msg, size_t msg_len, uint32_t type,
                            size_t off, size_t rdlen, int *malformed)
{
    char ipbuf[46];
    uint8_t ip16[16];

    switch (type) {
    case DNS_TYPE_A:
        if (rdlen != 4 || off + 4 > msg_len) {
            *malformed = 1;
            return (char *)protobuf_c_empty_string;
        }
        memset(ip16, 0, sizeof(ip16));
        memcpy(ip16, msg + off, 4);
        cf_format_ip(ipbuf, 4, ip16);
        return cf_dup_str(ipbuf);

    case DNS_TYPE_AAAA:
        if (rdlen != 16 || off + 16 > msg_len) {
            *malformed = 1;
            return (char *)protobuf_c_empty_string;
        }
        memcpy(ip16, msg + off, 16);
        cf_format_ip(ipbuf, 6, ip16);
        return cf_dup_str(ipbuf);

    case DNS_TYPE_NS:
    case DNS_TYPE_CNAME:
    case DNS_TYPE_PTR:
        return rdata_name_text(msg, msg_len, off, malformed);

    case DNS_TYPE_MX:
        return rdata_mx_text(msg, msg_len, off, rdlen, malformed);

    case DNS_TYPE_SRV:
        return rdata_srv_text(msg, msg_len, off, rdlen, malformed);

    case DNS_TYPE_SOA:
        return rdata_soa_text(msg, msg_len, off, rdlen, malformed);

    case DNS_TYPE_TXT:
        return rdata_txt_text(msg, msg_len, off, rdlen, malformed);

    default:
        return (char *)protobuf_c_empty_string;
    }
}

/* ---- header -------------------------------------------------------------- */

static Cloudflow__V1__DnsHeader *build_header(const uint8_t *msg, size_t msg_len)
{
    Cloudflow__V1__DnsHeader *h = calloc(1, sizeof(*h));
    uint16_t id, qd, an, ns, ar;
    uint8_t flags1, flags2;

    if (!h)
        return NULL;
    cloudflow__v1__dns_header__init(h);

    /* msg_len >= DNS_HEADER_LEN is guaranteed by the caller. */
    cf_get_be16(msg, msg_len, 0, &id);
    flags1 = msg[2];
    flags2 = msg[3];
    cf_get_be16(msg, msg_len, 4, &qd);
    cf_get_be16(msg, msg_len, 6, &an);
    cf_get_be16(msg, msg_len, 8, &ns);
    cf_get_be16(msg, msg_len, 10, &ar);

    h->id = id;
    h->qr = (flags1 & 0x80) != 0;
    h->opcode = (flags1 >> 3) & 0x0f;
    h->aa = (flags1 & 0x04) != 0;
    h->tc = (flags1 & 0x02) != 0;
    h->rd = (flags1 & 0x01) != 0;
    h->ra = (flags2 & 0x80) != 0;
    h->ad = (flags2 & 0x20) != 0;
    h->cd = (flags2 & 0x10) != 0;
    h->rcode = flags2 & 0x0f; /* low 4 bits; EDNS extended bits fold in later */
    h->qdcount = qd;
    h->ancount = an;
    h->nscount = ns;
    h->arcount = ar;

    return h;
}

/* ---- question section ---------------------------------------------------- */

/* Parses one question at *pos, appending a DnsQuestion to msg tree if
 * successful. Returns 1 if a question was produced (advancing *pos past it),
 * 0 if the section is truncated (caller stops). */
static Cloudflow__V1__DnsQuestion *
build_question(const uint8_t *msg, size_t msg_len, size_t *pos,
               size_t index, cf_warn_list_t *warnings)
{
    Cloudflow__V1__DnsQuestion *q;
    char name[DNS_NAME_BUF];
    size_t consumed;
    size_t name_start = *pos;
    uint16_t qtype, qclass;
    char path[48];
    char typescratch[16];
    int name_ok;

    name_ok = decode_name(msg, msg_len, name_start, 1, name, &consumed);
    if (consumed == 0) {
        /* Could not advance at all -- nothing usable remains. */
        snprintf(path, sizeof(path), "questions[%zu].qname", index);
        cf_warn(warnings, "dns_question_truncated",
                "question name runs past end of message", path, NULL, 0);
        return NULL;
    }
    if (!name_ok) {
        snprintf(path, sizeof(path), "questions[%zu].qname", index);
        cf_warn(warnings, "dns_name_malformed",
                "malformed compression/label in question name", path,
                msg + name_start,
                (msg_len - name_start) < 16 ? (msg_len - name_start) : 16);
    }

    if (!cf_get_be16(msg, msg_len, name_start + consumed, &qtype) ||
        !cf_get_be16(msg, msg_len, name_start + consumed + 2, &qclass)) {
        snprintf(path, sizeof(path), "questions[%zu]", index);
        cf_warn(warnings, "dns_question_truncated",
                "question type/class runs past end of message", path, NULL, 0);
        return NULL;
    }

    q = calloc(1, sizeof(*q));
    if (!q)
        return NULL;
    cloudflow__v1__dns_question__init(q);

    q->qname = cf_dup_str(name);
    /* qname_wire: the raw name bytes exactly as they appeared on the wire
     * (preserves DNS-0x20 casing), i.e. the span this name occupies here. */
    cf_set_bytes(&q->qname_wire, msg + name_start, consumed);
    q->qtype = qtype;
    q->qtype_name = cf_dup_str(dns_type_name(qtype, typescratch, sizeof(typescratch)));
    q->qclass = qclass;

    *pos = name_start + consumed + 4;
    return q;
}

/* ---- resource records ---------------------------------------------------- */

typedef struct {
    char name[DNS_NAME_BUF];
    int name_malformed;
    uint32_t type;
    uint32_t rr_class;
    uint32_t ttl;
    size_t rdata_off;
    size_t rdlength;
    int rdata_overrun;
} rr_hdr_t;

/* Reads the common RR header (name, type, class, ttl, rdlength) plus the
 * RDATA span, advancing *pos past the whole record. Returns 1 on success
 * (even for a length-overrun RDATA, which is clamped and flagged in
 * h->rdata_overrun), 0 if the fixed RR header itself is truncated (caller
 * stops the section). */
static int parse_rr_header(const uint8_t *msg, size_t msg_len, size_t *pos,
                           rr_hdr_t *h, cf_warn_list_t *warnings,
                           const char *section, size_t index)
{
    size_t name_start = *pos;
    size_t consumed;
    uint16_t type, rr_class, rdlength;
    uint32_t ttl;
    char path[64];

    h->name_malformed = 0;
    h->rdata_overrun = 0;

    if (!decode_name(msg, msg_len, name_start, 1, h->name, &consumed))
        h->name_malformed = 1;
    if (consumed == 0)
        return 0; /* name could not be advanced -> truncated */

    if (!cf_get_be16(msg, msg_len, name_start + consumed, &type) ||
        !cf_get_be16(msg, msg_len, name_start + consumed + 2, &rr_class) ||
        !cf_get_be32(msg, msg_len, name_start + consumed + 4, &ttl) ||
        !cf_get_be16(msg, msg_len, name_start + consumed + 8, &rdlength)) {
        snprintf(path, sizeof(path), "%s[%zu]", section, index);
        cf_warn(warnings, "dns_rr_truncated",
                "resource record header runs past end of message", path,
                NULL, 0);
        return 0;
    }

    h->type = type;
    h->rr_class = rr_class;
    h->ttl = ttl;
    h->rdata_off = name_start + consumed + 10;
    h->rdlength = rdlength;

    if (h->rdata_off + rdlength > msg_len) {
        /* Declared RDATA length overruns the buffer: clamp to what remains,
         * flag it, and let the caller stop after this record. */
        snprintf(path, sizeof(path), "%s[%zu].rdata", section, index);
        cf_warn(warnings, "dns_rdata_overrun",
                "record rdlength exceeds remaining message bytes", path,
                msg + h->rdata_off,
                (msg_len - h->rdata_off) < 16 ? (msg_len - h->rdata_off) : 16);
        h->rdlength = msg_len - h->rdata_off;
        h->rdata_overrun = 1;
        *pos = msg_len;
        return 1;
    }

    if (h->name_malformed) {
        snprintf(path, sizeof(path), "%s[%zu].name", section, index);
        cf_warn(warnings, "dns_name_malformed",
                "malformed compression/label in record name", path,
                msg + name_start,
                (msg_len - name_start) < 16 ? (msg_len - name_start) : 16);
    }

    *pos = h->rdata_off + rdlength;
    return 1;
}

/* Builds a DnsResourceRecord from a parsed RR header. */
static Cloudflow__V1__DnsResourceRecord *
build_rr(const uint8_t *msg, size_t msg_len, const rr_hdr_t *h)
{
    Cloudflow__V1__DnsResourceRecord *rr = calloc(1, sizeof(*rr));
    int malformed = h->name_malformed || h->rdata_overrun;
    char typescratch[16];

    if (!rr)
        return NULL;
    cloudflow__v1__dns_resource_record__init(rr);

    rr->name = cf_dup_str(h->name);
    rr->type = h->type;
    rr->type_name = cf_dup_str(dns_type_name(h->type, typescratch, sizeof(typescratch)));
    rr->class_ = h->rr_class;
    rr->ttl = h->ttl;
    cf_set_bytes(&rr->rdata_raw, msg + h->rdata_off, h->rdlength);
    rr->rdata_text = rdata_text_for(msg, msg_len, h->type, h->rdata_off,
                                    h->rdlength, &malformed);
    rr->malformed = malformed ? 1 : 0;

    return rr;
}

/* Appends `rr` to the (n_field, field) repeated array, growing it by one.
 * Frees `rr` and leaves the array unchanged on allocation failure. */
static void append_rr(size_t *n_field, Cloudflow__V1__DnsResourceRecord ***field,
                      Cloudflow__V1__DnsResourceRecord *rr)
{
    Cloudflow__V1__DnsResourceRecord **grown;

    grown = realloc(*field, (*n_field + 1) * sizeof(**field));
    if (!grown) {
        cloudflow__v1__dns_resource_record__free_unpacked(rr, NULL);
        return;
    }
    *field = grown;
    (*field)[*n_field] = rr;
    (*n_field)++;
}

/* ---- EDNS OPT ------------------------------------------------------------ */

/* Populates *out (a fresh DnsEdns) from an OPT pseudo-record's header fields
 * and RDATA. The OPT's CLASS carries the requestor's UDP payload size and its
 * TTL packs extended-rcode / version / flags. Options are walked as a
 * sequence of (code, length, value) triples. */
static Cloudflow__V1__DnsEdns *build_edns(const uint8_t *msg, size_t msg_len,
                                          const rr_hdr_t *h,
                                          cf_warn_list_t *warnings)
{
    Cloudflow__V1__DnsEdns *e = calloc(1, sizeof(*e));
    size_t p = h->rdata_off;
    size_t end = h->rdata_off + h->rdlength;
    Cloudflow__V1__DnsEdnsOption **opts = NULL;
    size_t n_opts = 0;

    if (!e)
        return NULL;
    cloudflow__v1__dns_edns__init(e);

    e->udp_payload_size = h->rr_class;
    e->extended_rcode = (h->ttl >> 24) & 0xff;
    e->version = (h->ttl >> 16) & 0xff;
    e->do_bit = (h->ttl & 0x8000) != 0;

    if (end > msg_len)
        end = msg_len;

    while (p + 4 <= end) {
        uint16_t code, olen;
        Cloudflow__V1__DnsEdnsOption *opt;
        Cloudflow__V1__DnsEdnsOption **grown;

        cf_get_be16(msg, msg_len, p, &code);
        cf_get_be16(msg, msg_len, p + 2, &olen);
        p += 4;
        if (p + olen > end) {
            cf_warn(warnings, "dns_edns_option_overrun",
                    "EDNS option length exceeds OPT rdata", "edns.options",
                    NULL, 0);
            olen = (uint16_t)(end - p);
        }

        opt = calloc(1, sizeof(*opt));
        if (!opt)
            break;
        cloudflow__v1__dns_edns_option__init(opt);
        opt->code = code;
        opt->name = cf_dup_str("");
        opt->length = olen;
        cf_set_bytes(&opt->raw_value, msg + p, olen);
        opt->decoded_text = cf_dup_str("");

        grown = realloc(opts, (n_opts + 1) * sizeof(*opts));
        if (!grown) {
            cloudflow__v1__dns_edns_option__free_unpacked(opt, NULL);
            break;
        }
        opts = grown;
        opts[n_opts++] = opt;

        p += olen;
    }

    e->n_options = n_opts;
    e->options = opts;
    return e;
}

/* ---- section drivers ----------------------------------------------------- */

static void parse_rr_section(const uint8_t *msg, size_t msg_len, size_t *pos,
                             uint16_t count, const char *section,
                             size_t *n_field,
                             Cloudflow__V1__DnsResourceRecord ***field,
                             cf_warn_list_t *warnings)
{
    for (uint16_t i = 0; i < count; i++) {
        rr_hdr_t h;
        Cloudflow__V1__DnsResourceRecord *rr;

        if (*pos >= msg_len) {
            cf_warn(warnings, "dns_section_truncated",
                    "record count exceeds available message bytes",
                    section, NULL, 0);
            break;
        }
        if (!parse_rr_header(msg, msg_len, pos, &h, warnings, section, i))
            break;

        rr = build_rr(msg, msg_len, &h);
        if (!rr)
            break;
        append_rr(n_field, field, rr);

        if (h.rdata_overrun)
            break; /* buffer exhausted; nothing reliable remains */
    }
}

/* ---- entry point --------------------------------------------------------- */

int cf_dns_parse(const uint8_t *msg, size_t msg_len,
                 Cloudflow__V1__DnsMessage **out, cf_warn_list_t *warnings)
{
    Cloudflow__V1__DnsMessage *m;
    size_t pos;

    if (out)
        *out = NULL;
    if (!msg || !out || msg_len < DNS_HEADER_LEN)
        return 0;

    m = calloc(1, sizeof(*m));
    if (!m)
        return 0;
    cloudflow__v1__dns_message__init(m);

    m->header = build_header(msg, msg_len);
    if (!m->header) {
        cloudflow__v1__dns_message__free_unpacked(m, NULL);
        return 0;
    }

    pos = DNS_HEADER_LEN;

    /* Questions. */
    for (uint16_t i = 0; i < m->header->qdcount; i++) {
        Cloudflow__V1__DnsQuestion *q;
        Cloudflow__V1__DnsQuestion **grown;

        if (pos >= msg_len) {
            cf_warn(warnings, "dns_section_truncated",
                    "qdcount exceeds available message bytes", "questions",
                    NULL, 0);
            break;
        }
        q = build_question(msg, msg_len, &pos, i, warnings);
        if (!q)
            break;

        grown = realloc(m->questions, (m->n_questions + 1) * sizeof(*m->questions));
        if (!grown) {
            cloudflow__v1__dns_question__free_unpacked(q, NULL);
            break;
        }
        m->questions = grown;
        m->questions[m->n_questions++] = q;
    }

    /* Answers and authority are ordinary RR sections. */
    parse_rr_section(msg, msg_len, &pos, m->header->ancount, "answers",
                     &m->n_answers, &m->answers, warnings);
    parse_rr_section(msg, msg_len, &pos, m->header->nscount, "authority",
                     &m->n_authority, &m->authority, warnings);

    /* Additional: the OPT (type 41) pseudo-record is diverted into
     * DnsMessage.edns instead of being emitted as an ordinary RR. */
    for (uint16_t i = 0; i < m->header->arcount; i++) {
        rr_hdr_t h;

        if (pos >= msg_len) {
            cf_warn(warnings, "dns_section_truncated",
                    "arcount exceeds available message bytes", "additional",
                    NULL, 0);
            break;
        }
        if (!parse_rr_header(msg, msg_len, &pos, &h, warnings, "additional", i))
            break;

        if (h.type == DNS_TYPE_OPT) {
            if (!m->edns) {
                m->edns = build_edns(msg, msg_len, &h, warnings);
                if (m->edns) {
                    /* Fold the extended rcode's high 8 bits into the header
                     * rcode: rcode = (extended_rcode << 4) | header_low4. */
                    m->header->rcode =
                        (m->edns->extended_rcode << 4) | (m->header->rcode & 0x0f);
                }
            } else {
                cf_warn(warnings, "dns_multiple_opt",
                        "more than one OPT pseudo-record in additional section",
                        "additional", NULL, 0);
            }
        } else {
            Cloudflow__V1__DnsResourceRecord *rr = build_rr(msg, msg_len, &h);
            if (!rr)
                break;
            append_rr(&m->n_additional, &m->additional, rr);
        }

        if (h.rdata_overrun)
            break;
    }

    *out = m;
    return 1;
}
