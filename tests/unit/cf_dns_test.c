/* CUnit acceptance tests for the WP-DNS03 DNS message parser
 * (libs/cloudflow-packet/cf_dns.c) and the shared parser utilities it builds
 * on (cf_parse_util.c). Standalone binary (build/cf_dns_test), following the
 * "one binary per WP" pattern documented in tests/unit/Makefile.
 *
 * Every case is driven by a hand-built DNS message byte array (the scapy
 * fixture corpus is a separate work package, WP-DNS09), covering a query, an
 * A/CNAME/MX response, name compression, EDNS0 OPT extraction, DNS-0x20 case
 * randomization, and the adversarial paths (forward/self compression
 * pointers, truncation, sub-header messages). A final micro-suite exercises
 * cf_parse_util directly.
 */

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cf_dns.h"
#include "cf_parse_util.h"

/* ---- tiny DNS message builder -------------------------------------------- */

typedef struct {
    uint8_t b[1024];
    size_t n;
} buf_t;

static void buf_init(buf_t *m) { m->n = 0; }

static void put_u8(buf_t *m, uint8_t v) { m->b[m->n++] = v; }

static void put_be16(buf_t *m, uint16_t v)
{
    m->b[m->n++] = (uint8_t)(v >> 8);
    m->b[m->n++] = (uint8_t)(v & 0xff);
}

static void put_be32(buf_t *m, uint32_t v)
{
    m->b[m->n++] = (uint8_t)(v >> 24);
    m->b[m->n++] = (uint8_t)(v >> 16);
    m->b[m->n++] = (uint8_t)(v >> 8);
    m->b[m->n++] = (uint8_t)(v & 0xff);
}

static void put_bytes(buf_t *m, const uint8_t *p, size_t len)
{
    memcpy(m->b + m->n, p, len);
    m->n += len;
}

/* Encodes `dotted` (e.g. "example.com", or "" for the root) as wire-format
 * length-prefixed labels terminated by a zero octet. */
static void put_name(buf_t *m, const char *dotted)
{
    const char *p = dotted;

    while (*p) {
        const char *dot = strchr(p, '.');
        size_t len = dot ? (size_t)(dot - p) : strlen(p);
        put_u8(m, (uint8_t)len);
        put_bytes(m, (const uint8_t *)p, len);
        p += len;
        if (dot)
            p++; /* skip the '.' */
    }
    put_u8(m, 0);
}

static void put_header(buf_t *m, uint16_t id, uint8_t flags1, uint8_t flags2,
                       uint16_t qd, uint16_t an, uint16_t ns, uint16_t ar)
{
    put_be16(m, id);
    put_u8(m, flags1);
    put_u8(m, flags2);
    put_be16(m, qd);
    put_be16(m, an);
    put_be16(m, ns);
    put_be16(m, ar);
}

/* ---- helpers ------------------------------------------------------------- */

static void free_warnings(cf_warn_list_t *w)
{
    size_t n;
    Cloudflow__V1__ParserWarning **items;
    size_t i;

    cf_warn_list_take(w, &n, &items);
    for (i = 0; i < n; i++)
        cloudflow__v1__parser_warning__free_unpacked(items[i], NULL);
    free(items);
}

/* ---- single-question query ------------------------------------------------ */

static void test_query_example_com(void)
{
    buf_t m;
    Cloudflow__V1__DnsMessage *msg = NULL;
    cf_warn_list_t w;
    int rc;

    cf_warn_list_init(&w);
    buf_init(&m);
    put_header(&m, 0x1234, 0x01, 0x00, 1, 0, 0, 0); /* rd set */
    put_name(&m, "example.com");
    put_be16(&m, 1); /* qtype A */
    put_be16(&m, 1); /* qclass IN */

    rc = cf_dns_parse(m.b, m.n, &msg, &w);
    CU_ASSERT_EQUAL_FATAL(rc, 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(msg);
    CU_ASSERT_PTR_NOT_NULL_FATAL(msg->header);

    CU_ASSERT_EQUAL(msg->header->id, 0x1234);
    CU_ASSERT_FALSE(msg->header->qr);
    CU_ASSERT_TRUE(msg->header->rd);
    CU_ASSERT_EQUAL(msg->header->opcode, 0);
    CU_ASSERT_EQUAL(msg->header->qdcount, 1);
    CU_ASSERT_EQUAL(msg->header->rcode, 0);

    CU_ASSERT_EQUAL_FATAL(msg->n_questions, 1);
    CU_ASSERT_STRING_EQUAL(msg->questions[0]->qname, "example.com");
    CU_ASSERT_STRING_EQUAL(msg->questions[0]->qtype_name, "A");
    CU_ASSERT_EQUAL(msg->questions[0]->qtype, 1);
    CU_ASSERT_EQUAL(msg->questions[0]->qclass, 1);
    /* qname_wire is the raw wire encoding: 07 'e'..'e' 03 'c' 'o' 'm' 00. */
    CU_ASSERT_EQUAL(msg->questions[0]->qname_wire.len, 13);
    CU_ASSERT_EQUAL(msg->questions[0]->qname_wire.data[0], 7);

    cloudflow__v1__dns_message__free_unpacked(msg, NULL);
    free_warnings(&w);
}

/* ---- A response ----------------------------------------------------------- */

static void test_response_a(void)
{
    buf_t m;
    Cloudflow__V1__DnsMessage *msg = NULL;
    cf_warn_list_t w;
    static const uint8_t a_rdata[4] = {192, 0, 2, 1};

    cf_warn_list_init(&w);
    buf_init(&m);
    put_header(&m, 0xabcd, 0x81, 0x80, 1, 1, 0, 0); /* qr, rd, ra */
    put_name(&m, "example.com");
    put_be16(&m, 1);
    put_be16(&m, 1);
    /* answer: literal name, A record, ttl 3600, 192.0.2.1 */
    put_name(&m, "example.com");
    put_be16(&m, 1);       /* type A */
    put_be16(&m, 1);       /* class IN */
    put_be32(&m, 3600);    /* ttl */
    put_be16(&m, 4);       /* rdlength */
    put_bytes(&m, a_rdata, 4);

    CU_ASSERT_EQUAL_FATAL(cf_dns_parse(m.b, m.n, &msg, &w), 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(msg);
    CU_ASSERT_TRUE(msg->header->qr);
    CU_ASSERT_TRUE(msg->header->ra);
    CU_ASSERT_EQUAL_FATAL(msg->n_answers, 1);
    CU_ASSERT_STRING_EQUAL(msg->answers[0]->type_name, "A");
    CU_ASSERT_EQUAL(msg->answers[0]->ttl, 3600);
    CU_ASSERT_STRING_EQUAL(msg->answers[0]->rdata_text, "192.0.2.1");
    CU_ASSERT_FALSE(msg->answers[0]->malformed);

    cloudflow__v1__dns_message__free_unpacked(msg, NULL);
    free_warnings(&w);
}

/* ---- A response with a compression pointer for the answer name ------------ */

static void test_response_compressed_name(void)
{
    buf_t m;
    Cloudflow__V1__DnsMessage *msg = NULL;
    cf_warn_list_t w;
    static const uint8_t a_rdata[4] = {192, 0, 2, 42};

    cf_warn_list_init(&w);
    buf_init(&m);
    put_header(&m, 0x0001, 0x81, 0x80, 1, 1, 0, 0);
    put_name(&m, "example.com"); /* question name at offset 12 */
    put_be16(&m, 1);
    put_be16(&m, 1);
    /* answer name is a compression pointer back to offset 12 (0xC00C). */
    put_u8(&m, 0xc0);
    put_u8(&m, 0x0c);
    put_be16(&m, 1);
    put_be16(&m, 1);
    put_be32(&m, 300);
    put_be16(&m, 4);
    put_bytes(&m, a_rdata, 4);

    CU_ASSERT_EQUAL_FATAL(cf_dns_parse(m.b, m.n, &msg, &w), 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(msg);
    CU_ASSERT_EQUAL_FATAL(msg->n_answers, 1);
    CU_ASSERT_STRING_EQUAL(msg->answers[0]->name, "example.com");
    CU_ASSERT_STRING_EQUAL(msg->answers[0]->rdata_text, "192.0.2.42");
    CU_ASSERT_FALSE(msg->answers[0]->malformed);

    cloudflow__v1__dns_message__free_unpacked(msg, NULL);
    free_warnings(&w);
}

/* ---- CNAME + MX response -------------------------------------------------- */

static void test_response_cname_mx(void)
{
    buf_t m;
    Cloudflow__V1__DnsMessage *msg = NULL;
    cf_warn_list_t w;
    buf_t namebuf;

    cf_warn_list_init(&w);
    buf_init(&m);
    put_header(&m, 0x2222, 0x81, 0x80, 1, 2, 0, 0);
    put_name(&m, "example.com");
    put_be16(&m, 1);
    put_be16(&m, 1);

    /* answer 1: CNAME -> www.example.net */
    put_name(&m, "example.com");
    put_be16(&m, 5);    /* CNAME */
    put_be16(&m, 1);
    put_be32(&m, 60);
    buf_init(&namebuf);
    put_name(&namebuf, "www.example.net");
    put_be16(&m, (uint16_t)namebuf.n);
    put_bytes(&m, namebuf.b, namebuf.n);

    /* answer 2: MX pref 10 exchange mail.example.com */
    put_name(&m, "example.com");
    put_be16(&m, 15);   /* MX */
    put_be16(&m, 1);
    put_be32(&m, 60);
    buf_init(&namebuf);
    put_be16(&namebuf, 10); /* preference */
    put_name(&namebuf, "mail.example.com");
    put_be16(&m, (uint16_t)namebuf.n);
    put_bytes(&m, namebuf.b, namebuf.n);

    CU_ASSERT_EQUAL_FATAL(cf_dns_parse(m.b, m.n, &msg, &w), 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(msg);
    CU_ASSERT_EQUAL_FATAL(msg->n_answers, 2);
    CU_ASSERT_STRING_EQUAL(msg->answers[0]->type_name, "CNAME");
    CU_ASSERT_STRING_EQUAL(msg->answers[0]->rdata_text, "www.example.net");
    CU_ASSERT_STRING_EQUAL(msg->answers[1]->type_name, "MX");
    CU_ASSERT_STRING_EQUAL(msg->answers[1]->rdata_text, "10 mail.example.com");

    cloudflow__v1__dns_message__free_unpacked(msg, NULL);
    free_warnings(&w);
}

/* ---- EDNS OPT in the additional section ----------------------------------- */

static void test_edns_opt(void)
{
    buf_t m;
    Cloudflow__V1__DnsMessage *msg = NULL;
    cf_warn_list_t w;
    static const uint8_t a_rdata[4] = {198, 51, 100, 7};
    static const uint8_t cookie[8] = {1, 2, 3, 4, 5, 6, 7, 8};

    cf_warn_list_init(&w);
    buf_init(&m);
    /* header rcode low 4 bits = 0; EDNS extended rcode top byte = 1. */
    put_header(&m, 0x3333, 0x81, 0x80, 1, 1, 0, 1);
    put_name(&m, "example.com");
    put_be16(&m, 1);
    put_be16(&m, 1);
    /* one ordinary A answer */
    put_name(&m, "example.com");
    put_be16(&m, 1);
    put_be16(&m, 1);
    put_be32(&m, 120);
    put_be16(&m, 4);
    put_bytes(&m, a_rdata, 4);
    /* OPT pseudo-record: root name, type 41, class = udp payload size 4096,
     * ttl = extended_rcode(1)<<24 | version(0)<<16 | flags(0x8000 DO). */
    put_name(&m, "");
    put_be16(&m, 41);
    put_be16(&m, 4096);
    put_be32(&m, 0x01008000u);
    /* rdata: one option, code 10 (cookie), len 8. */
    put_be16(&m, 4 + 8); /* rdlength */
    put_be16(&m, 10);    /* option code */
    put_be16(&m, 8);     /* option length */
    put_bytes(&m, cookie, 8);

    CU_ASSERT_EQUAL_FATAL(cf_dns_parse(m.b, m.n, &msg, &w), 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(msg);
    /* The OPT is NOT emitted as an ordinary additional RR. */
    CU_ASSERT_EQUAL(msg->n_additional, 0);
    CU_ASSERT_EQUAL_FATAL(msg->n_answers, 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(msg->edns);
    CU_ASSERT_EQUAL(msg->edns->udp_payload_size, 4096);
    CU_ASSERT_TRUE(msg->edns->do_bit);
    CU_ASSERT_EQUAL(msg->edns->extended_rcode, 1);
    CU_ASSERT_EQUAL(msg->edns->version, 0);
    /* extended rcode folded into header rcode: (1 << 4) | 0 == 16. */
    CU_ASSERT_EQUAL(msg->header->rcode, 16);
    CU_ASSERT_EQUAL_FATAL(msg->edns->n_options, 1);
    CU_ASSERT_EQUAL(msg->edns->options[0]->code, 10);
    CU_ASSERT_EQUAL(msg->edns->options[0]->raw_value.len, 8);

    cloudflow__v1__dns_message__free_unpacked(msg, NULL);
    free_warnings(&w);
}

/* ---- DNS-0x20 mixed-case qname -------------------------------------------- */

static void test_dns_0x20_case(void)
{
    buf_t m;
    Cloudflow__V1__DnsMessage *msg = NULL;
    cf_warn_list_t w;

    cf_warn_list_init(&w);
    buf_init(&m);
    put_header(&m, 0x4444, 0x01, 0x00, 1, 0, 0, 0);
    put_name(&m, "ExAmPle.CoM");
    put_be16(&m, 1);
    put_be16(&m, 1);

    CU_ASSERT_EQUAL_FATAL(cf_dns_parse(m.b, m.n, &msg, &w), 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(msg);
    CU_ASSERT_EQUAL_FATAL(msg->n_questions, 1);
    /* qname is lowercased presentation form... */
    CU_ASSERT_STRING_EQUAL(msg->questions[0]->qname, "example.com");
    /* ...while qname_wire preserves the original 0x20 casing. */
    CU_ASSERT_EQUAL_FATAL(msg->questions[0]->qname_wire.len, 13);
    CU_ASSERT_EQUAL(msg->questions[0]->qname_wire.data[1], 'E');
    CU_ASSERT_EQUAL(msg->questions[0]->qname_wire.data[2], 'x');
    CU_ASSERT_EQUAL(msg->questions[0]->qname_wire.data[9], 'C');

    cloudflow__v1__dns_message__free_unpacked(msg, NULL);
    free_warnings(&w);
}

/* ---- adversarial: forward/self compression pointer ------------------------ */

static void test_bad_pointer_self(void)
{
    buf_t m;
    Cloudflow__V1__DnsMessage *msg = NULL;
    cf_warn_list_t w;
    static const uint8_t a_rdata[4] = {203, 0, 113, 9};
    size_t nwarn;
    Cloudflow__V1__ParserWarning **witems;

    cf_warn_list_init(&w);
    buf_init(&m);
    put_header(&m, 0x5555, 0x81, 0x80, 0, 1, 0, 0); /* qd=0, an=1 */
    /* answer name at offset 12 is a pointer to offset 12 -- itself. Must be
     * rejected (not followed, no loop, no overrun). */
    put_u8(&m, 0xc0);
    put_u8(&m, 0x0c);
    put_be16(&m, 1);
    put_be16(&m, 1);
    put_be32(&m, 30);
    put_be16(&m, 4);
    put_bytes(&m, a_rdata, 4);

    /* Message is still returned (header parsed); the RR is flagged malformed
     * and a warning is emitted. Critically: no hang / no crash. */
    CU_ASSERT_EQUAL_FATAL(cf_dns_parse(m.b, m.n, &msg, &w), 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(msg);
    CU_ASSERT_EQUAL_FATAL(msg->n_answers, 1);
    CU_ASSERT_TRUE(msg->answers[0]->malformed);

    cf_warn_list_take(&w, &nwarn, &witems);
    CU_ASSERT_TRUE(nwarn >= 1);
    for (size_t i = 0; i < nwarn; i++)
        cloudflow__v1__parser_warning__free_unpacked(witems[i], NULL);
    free(witems);

    cloudflow__v1__dns_message__free_unpacked(msg, NULL);
}

/* ---- adversarial: truncated section (count exceeds bytes) ------------------ */

static void test_truncated_counts(void)
{
    buf_t m;
    Cloudflow__V1__DnsMessage *msg = NULL;
    cf_warn_list_t w;
    size_t nwarn;
    Cloudflow__V1__ParserWarning **witems;

    cf_warn_list_init(&w);
    buf_init(&m);
    /* Claims 5 answers but supplies none. */
    put_header(&m, 0x6666, 0x81, 0x80, 1, 5, 0, 0);
    put_name(&m, "example.com");
    put_be16(&m, 1);
    put_be16(&m, 1);

    CU_ASSERT_EQUAL_FATAL(cf_dns_parse(m.b, m.n, &msg, &w), 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(msg);
    CU_ASSERT_EQUAL(msg->n_questions, 1);
    CU_ASSERT_EQUAL(msg->n_answers, 0); /* safe partial parse */

    cf_warn_list_take(&w, &nwarn, &witems);
    CU_ASSERT_TRUE(nwarn >= 1);
    for (size_t i = 0; i < nwarn; i++)
        cloudflow__v1__parser_warning__free_unpacked(witems[i], NULL);
    free(witems);

    cloudflow__v1__dns_message__free_unpacked(msg, NULL);
}

/* ---- sub-header message ---------------------------------------------------- */

static void test_too_short(void)
{
    uint8_t tiny[8] = {0};
    Cloudflow__V1__DnsMessage *msg = (void *)0x1;
    cf_warn_list_t w;

    cf_warn_list_init(&w);
    CU_ASSERT_EQUAL(cf_dns_parse(tiny, sizeof(tiny), &msg, &w), 0);
    CU_ASSERT_PTR_NULL(msg);
    free_warnings(&w);
}

/* ---- never crashes: truncation + bit-flip sweep --------------------------- */

/* Builds a moderately rich message (query + A answer via a compression
 * pointer + an OPT), then parses every truncation of it and every single-bit
 * flip of every byte. None may crash, hang, or read out of bounds -- the
 * point of the ASan build. Any returned message is freed. */
static void test_never_crashes(void)
{
    buf_t m;
    static const uint8_t a_rdata[4] = {192, 0, 2, 1};
    size_t total, i;
    int bit;

    buf_init(&m);
    put_header(&m, 0x7777, 0x81, 0x80, 1, 1, 0, 1);
    put_name(&m, "a.example.com");
    put_be16(&m, 1);
    put_be16(&m, 1);
    put_u8(&m, 0xc0);   /* answer name: compression pointer to offset 12 */
    put_u8(&m, 0x0c);
    put_be16(&m, 1);
    put_be16(&m, 1);
    put_be32(&m, 300);
    put_be16(&m, 4);
    put_bytes(&m, a_rdata, 4);
    put_name(&m, "");   /* OPT */
    put_be16(&m, 41);
    put_be16(&m, 1232);
    put_be32(&m, 0x00008000u);
    put_be16(&m, 0);
    total = m.n;

    for (i = 0; i <= total; i++) {
        Cloudflow__V1__DnsMessage *msg = NULL;
        cf_warn_list_t w;
        cf_warn_list_init(&w);
        if (cf_dns_parse(m.b, i, &msg, &w))
            cloudflow__v1__dns_message__free_unpacked(msg, NULL);
        free_warnings(&w);
    }

    for (i = 0; i < total; i++) {
        uint8_t saved = m.b[i];
        for (bit = 0; bit < 8; bit++) {
            Cloudflow__V1__DnsMessage *msg = NULL;
            cf_warn_list_t w;
            cf_warn_list_init(&w);
            m.b[i] = (uint8_t)(saved ^ (1u << bit));
            if (cf_dns_parse(m.b, total, &msg, &w))
                cloudflow__v1__dns_message__free_unpacked(msg, NULL);
            free_warnings(&w);
        }
        m.b[i] = saved;
    }

    CU_PASS("no crash across truncation sweep and single-bit-flip sweep");
}

/* ---- cf_parse_util micro-test --------------------------------------------- */

static void test_parse_util(void)
{
    static const uint8_t data[4] = {0x12, 0x34, 0x56, 0x78};
    uint16_t v16 = 0xeeee;
    char *s;
    cf_warn_list_t w;
    size_t n;
    Cloudflow__V1__ParserWarning **items;

    /* cf_get_be16 bounds: an in-range read succeeds and byte-swaps... */
    CU_ASSERT_EQUAL(cf_get_be16(data, sizeof(data), 0, &v16), 1);
    CU_ASSERT_EQUAL(v16, 0x1234);
    CU_ASSERT_EQUAL(cf_get_be16(data, sizeof(data), 2, &v16), 1);
    CU_ASSERT_EQUAL(v16, 0x5678);
    /* ...an out-of-range read returns 0 and leaves *out untouched. */
    v16 = 0xaaaa;
    CU_ASSERT_EQUAL(cf_get_be16(data, sizeof(data), 3, &v16), 0);
    CU_ASSERT_EQUAL(v16, 0xaaaa);

    /* cf_hex_encode */
    s = cf_hex_encode(data, 4);
    CU_ASSERT_STRING_EQUAL(s, "12345678");
    free(s);

    /* cf_dup_strn */
    s = cf_dup_strn((const uint8_t *)"abcXYZ", 3);
    CU_ASSERT_STRING_EQUAL(s, "abc");
    free(s);

    /* cf_warn / cf_warn_list_take round-trip */
    cf_warn_list_init(&w);
    cf_warn(&w, "code_a", "message a", "field.a", data, sizeof(data));
    cf_warn(&w, "code_b", "message b", "field.b", NULL, 0);
    cf_warn_list_take(&w, &n, &items);
    CU_ASSERT_EQUAL_FATAL(n, 2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(items);
    CU_ASSERT_STRING_EQUAL(items[0]->code, "code_a");
    CU_ASSERT_EQUAL(items[0]->raw_context.len, 4);
    CU_ASSERT_STRING_EQUAL(items[1]->field_path, "field.b");
    CU_ASSERT_EQUAL(items[1]->raw_context.len, 0);
    for (size_t i = 0; i < n; i++)
        cloudflow__v1__parser_warning__free_unpacked(items[i], NULL);
    free(items);

    /* An empty list hands back NULL / 0. */
    cf_warn_list_init(&w);
    cf_warn_list_take(&w, &n, &items);
    CU_ASSERT_EQUAL(n, 0);
    CU_ASSERT_PTR_NULL(items);
}

/* ---- driver --------------------------------------------------------------- */

int main(void)
{
    CU_pSuite suite;
    unsigned int failed;

    if (CU_initialize_registry() != CUE_SUCCESS)
        return (int)CU_get_error();

    suite = CU_add_suite("cf_dns", NULL, NULL);
    if (!suite) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    if (!CU_add_test(suite, "single-question query", test_query_example_com) ||
        !CU_add_test(suite, "A response rdata_text", test_response_a) ||
        !CU_add_test(suite, "compressed answer name", test_response_compressed_name) ||
        !CU_add_test(suite, "CNAME + MX response", test_response_cname_mx) ||
        !CU_add_test(suite, "EDNS OPT extraction + rcode fold", test_edns_opt) ||
        !CU_add_test(suite, "DNS-0x20 mixed-case qname", test_dns_0x20_case) ||
        !CU_add_test(suite, "adversarial self/forward pointer", test_bad_pointer_self) ||
        !CU_add_test(suite, "truncated section counts", test_truncated_counts) ||
        !CU_add_test(suite, "sub-header message -> 0", test_too_short) ||
        !CU_add_test(suite, "never crashes: truncation + bit-flip sweep", test_never_crashes) ||
        !CU_add_test(suite, "cf_parse_util micro-test", test_parse_util)) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();

    failed = CU_get_number_of_tests_failed();

    CU_cleanup_registry();

    return failed > 0 ? 1 : 0;
}
