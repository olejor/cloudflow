/* CUnit acceptance tests for the WP-07 DHCPv6 parser
 * (libs/cloudflow-packet/cf_dhcpv6*.c). Standalone binary
 * (build/cf_dhcpv6_test), following the "one binary per WP" pattern
 * documented in tests/unit/Makefile (mirrors cf_dhcpv4_test.c's structure
 * and pcap-reading helper).
 *
 * Fixture-driven tests load a pcap from tests/fixtures/dhcp/ (built by
 * generate_fixtures.py), extract the UDP payload via cf_decap_udp (WP-05),
 * and parse it with cf_dhcpv6_parse, asserting the core fields the
 * fixture's <name>.expected.md documents. A handful of additional tests
 * build DHCPv6 payloads directly to cover parser paths no single fixture
 * exercises on its own (too-short payload, a truncation/bit-flip
 * robustness sweep, and a pack/unpack round trip).
 */

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cf_decap.h"
#include "cf_dhcpv6.h"

#ifndef FIXTURES_DIR
#define FIXTURES_DIR "../fixtures/dhcp"
#endif

/* ---- tiny classic-pcap reader (identical shape to cf_dhcpv4_test.c's) ---- */

static uint32_t rd_u32_endian(const uint8_t *p, int big_endian)
{
    if (big_endian)
        return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
               ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[1] << 8) | (uint32_t)p[0];
}

static int read_first_pcap_frame(const char *path, uint8_t *buf, size_t bufcap,
                                  size_t *out_len)
{
    FILE *f;
    uint8_t ghdr[24], rhdr[16];
    uint32_t magic_le, magic_be, incl_len;
    int big_endian;

    f = fopen(path, "rb");
    if (!f)
        return 0;

    if (fread(ghdr, 1, sizeof(ghdr), f) != sizeof(ghdr)) {
        fclose(f);
        return 0;
    }

    magic_le = rd_u32_endian(ghdr, 0);
    magic_be = rd_u32_endian(ghdr, 1);
    if (magic_le == 0xa1b2c3d4u || magic_le == 0xa1b23c4du)
        big_endian = 0;
    else if (magic_be == 0xa1b2c3d4u || magic_be == 0xa1b23c4du)
        big_endian = 1;
    else {
        fclose(f);
        return 0;
    }

    if (fread(rhdr, 1, sizeof(rhdr), f) != sizeof(rhdr)) {
        fclose(f);
        return 0;
    }

    incl_len = rd_u32_endian(rhdr + 8, big_endian);
    if (incl_len == 0 || incl_len > bufcap) {
        fclose(f);
        return 0;
    }
    if (fread(buf, 1, incl_len, f) != incl_len) {
        fclose(f);
        return 0;
    }

    fclose(f);
    *out_len = incl_len;
    return 1;
}

static Cloudflow__V1__DhcpV6PacketEvent *load_fixture(const char *name,
                                                        const char **event_type,
                                                        cf_decap_udp_t *decap_out)
{
    char path[512];
    static uint8_t frame[4096];
    size_t frame_len;
    cf_decap_udp_t decap;
    cf_decap_result_t rc;

    snprintf(path, sizeof(path), "%s/%s.pcap", FIXTURES_DIR, name);

    if (!read_first_pcap_frame(path, frame, sizeof(frame), &frame_len)) {
        CU_FAIL("failed to read fixture pcap (run tests/fixtures/dhcp/generate_fixtures.py?)");
        return NULL;
    }

    rc = cf_decap_udp(frame, frame_len, &decap);
    if (rc != CF_DECAP_OK) {
        CU_FAIL("cf_decap_udp did not return CF_DECAP_OK for fixture frame");
        return NULL;
    }
    if (decap_out)
        *decap_out = decap;

    return cf_dhcpv6_parse(decap.payload, decap.payload_len, event_type);
}

static const uint8_t V6_CLIENT_MAC[6] = {0x02, 0x00, 0x5e, 0x20, 0x00, 0x01};
static const uint8_t V6_SERVER_MAC[6] = {0x02, 0x00, 0x5e, 0x20, 0x00, 0x02};

/* DUID-LL (RFC 8415 11.4): type=3, hwtype=1 (Ethernet), 6-byte MAC. */
static void expect_duid_ll(const ProtobufCBinaryData *duid, const uint8_t mac[6])
{
    uint8_t expected[10] = {0, 3, 0, 1};

    memcpy(expected + 4, mac, 6);
    CU_ASSERT_EQUAL(duid->len, sizeof(expected));
    if (duid->len == sizeof(expected))
        CU_ASSERT_EQUAL(memcmp(duid->data, expected, sizeof(expected)), 0);
}

/* ---- v6_solicit ------------------------------------------------------------ */

static void test_v6_solicit(void)
{
    const char *event_type = NULL;
    Cloudflow__V1__DhcpV6PacketEvent *ev = load_fixture("v6_solicit", &event_type, NULL);

    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);
    CU_ASSERT_STRING_EQUAL(event_type, "dhcpv6.solicit.observed");

    CU_ASSERT_EQUAL(ev->header->message_type, CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__SOLICIT);
    CU_ASSERT_EQUAL(ev->header->transaction_id, 0x101010u);

    expect_duid_ll(&ev->decoded->client_duid, V6_CLIENT_MAC);

    CU_ASSERT_EQUAL(ev->decoded->n_option_request_option_codes, 3);
    if (ev->decoded->n_option_request_option_codes == 3) {
        CU_ASSERT_EQUAL(ev->decoded->option_request_option_codes[0], 23);
        CU_ASSERT_EQUAL(ev->decoded->option_request_option_codes[1], 24);
        CU_ASSERT_EQUAL(ev->decoded->option_request_option_codes[2], 31);
    }

    CU_ASSERT_EQUAL(ev->decoded->n_assigned_addresses, 0);
    CU_ASSERT_EQUAL(ev->n_parser_warnings, 0);
    CU_ASSERT_TRUE(ev->raw_dhcp_payload.len > 0);

    /* pack/unpack round trip */
    {
        size_t plen = cloudflow__v1__dhcp_v6_packet_event__get_packed_size(ev);
        uint8_t *packed = malloc(plen);
        Cloudflow__V1__DhcpV6PacketEvent *rt;

        CU_ASSERT_PTR_NOT_NULL_FATAL(packed);
        CU_ASSERT_EQUAL(cloudflow__v1__dhcp_v6_packet_event__pack(ev, packed), plen);

        rt = cloudflow__v1__dhcp_v6_packet_event__unpack(NULL, plen, packed);
        CU_ASSERT_PTR_NOT_NULL_FATAL(rt);
        CU_ASSERT_EQUAL(rt->header->transaction_id, 0x101010u);
        CU_ASSERT_EQUAL(rt->header->message_type,
                         CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__SOLICIT);
        CU_ASSERT_EQUAL(rt->n_raw_options, ev->n_raw_options);
        CU_ASSERT_EQUAL(rt->decoded->n_option_request_option_codes,
                         ev->decoded->n_option_request_option_codes);

        cloudflow__v1__dhcp_v6_packet_event__free_unpacked(rt, NULL);
        free(packed);
    }

    cf_dhcpv6_event_free(ev);
}

/* ---- v6_advertise ------------------------------------------------------- */

static void test_v6_advertise(void)
{
    const char *event_type = NULL;
    Cloudflow__V1__DhcpV6PacketEvent *ev = load_fixture("v6_advertise", &event_type, NULL);

    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);
    CU_ASSERT_STRING_EQUAL(event_type, "dhcpv6.advertise.observed");
    CU_ASSERT_EQUAL(ev->header->message_type,
                     CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__ADVERTISE);
    CU_ASSERT_EQUAL(ev->header->transaction_id, 0x101010u);

    expect_duid_ll(&ev->decoded->server_duid, V6_SERVER_MAC);
    expect_duid_ll(&ev->decoded->client_duid, V6_CLIENT_MAC);

    CU_ASSERT_EQUAL(ev->decoded->n_assigned_addresses, 1);
    if (ev->decoded->n_assigned_addresses == 1)
        CU_ASSERT_STRING_EQUAL(ev->decoded->assigned_addresses[0], "2001:db8::50");

    cf_dhcpv6_event_free(ev);
}

/* ---- v6_request ----------------------------------------------------------- */

static void test_v6_request(void)
{
    const char *event_type = NULL;
    Cloudflow__V1__DhcpV6PacketEvent *ev = load_fixture("v6_request", &event_type, NULL);

    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);
    CU_ASSERT_STRING_EQUAL(event_type, "dhcpv6.request.observed");
    CU_ASSERT_EQUAL(ev->header->message_type, CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__REQUEST);
    CU_ASSERT_EQUAL(ev->header->transaction_id, 0x202020u);

    expect_duid_ll(&ev->decoded->client_duid, V6_CLIENT_MAC);
    expect_duid_ll(&ev->decoded->server_duid, V6_SERVER_MAC);

    CU_ASSERT_EQUAL(ev->decoded->n_option_request_option_codes, 2);
    if (ev->decoded->n_option_request_option_codes == 2) {
        CU_ASSERT_EQUAL(ev->decoded->option_request_option_codes[0], 23);
        CU_ASSERT_EQUAL(ev->decoded->option_request_option_codes[1], 24);
    }

    CU_ASSERT_EQUAL(ev->decoded->n_assigned_addresses, 1);
    if (ev->decoded->n_assigned_addresses == 1)
        CU_ASSERT_STRING_EQUAL(ev->decoded->assigned_addresses[0], "2001:db8::50");

    cf_dhcpv6_event_free(ev);
}

/* ---- v6_reply --------------------------------------------------------------- */

static void test_v6_reply(void)
{
    const char *event_type = NULL;
    Cloudflow__V1__DhcpV6PacketEvent *ev = load_fixture("v6_reply", &event_type, NULL);

    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);
    CU_ASSERT_STRING_EQUAL(event_type, "dhcpv6.reply.observed");
    CU_ASSERT_EQUAL(ev->header->message_type, CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__REPLY);
    CU_ASSERT_EQUAL(ev->header->transaction_id, 0x202020u);

    expect_duid_ll(&ev->decoded->server_duid, V6_SERVER_MAC);

    CU_ASSERT_EQUAL(ev->decoded->n_assigned_addresses, 1);
    if (ev->decoded->n_assigned_addresses == 1)
        CU_ASSERT_STRING_EQUAL(ev->decoded->assigned_addresses[0], "2001:db8::50");

    cf_dhcpv6_event_free(ev);
}

/* ---- v6_relay_forw ----------------------------------------------------------- */

static void test_v6_relay_forw(void)
{
    const char *event_type = NULL;
    Cloudflow__V1__DhcpV6PacketEvent *ev = load_fixture("v6_relay_forw", &event_type, NULL);
    size_t i;
    int saw_relay_msg_option = 0;
    int saw_interface_id_option = 0;

    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);
    CU_ASSERT_STRING_EQUAL(event_type, "dhcpv6.relay-forw.observed");
    CU_ASSERT_EQUAL(ev->header->message_type,
                     CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__RELAY_FORW);
    CU_ASSERT_EQUAL(ev->header->hop_count, 0);
    CU_ASSERT_STRING_EQUAL(ev->header->link_address, "2001:db8:1::1");
    CU_ASSERT_STRING_EQUAL(ev->header->peer_address, "fe80::200:5eff:fe20:1");

    /* Outer message carries no DUID/IA_NA/ORO of its own: the inner SOLICIT
     * is opaque raw bytes inside option 9, not recursively parsed. */
    CU_ASSERT_EQUAL(ev->decoded->client_duid.len, 0);
    CU_ASSERT_EQUAL(ev->decoded->n_assigned_addresses, 0);

    for (i = 0; i < ev->n_raw_options; i++) {
        Cloudflow__V1__DhcpV6Option *opt = ev->raw_options[i];

        if (opt->code == 9) {
            saw_relay_msg_option = 1;
            CU_ASSERT_TRUE(opt->raw_value.len > 4);
            /* Inner message's own msg-type/xid, verbatim in the raw bytes. */
            if (opt->raw_value.len >= 4) {
                CU_ASSERT_EQUAL(opt->raw_value.data[0], 1); /* SOLICIT */
                CU_ASSERT_EQUAL(opt->raw_value.data[1], 0x30);
                CU_ASSERT_EQUAL(opt->raw_value.data[2], 0x30);
                CU_ASSERT_EQUAL(opt->raw_value.data[3], 0x30);
            }
        }
        if (opt->code == 18) {
            saw_interface_id_option = 1;
            CU_ASSERT_EQUAL(opt->raw_value.len, 4);
            if (opt->raw_value.len == 4)
                CU_ASSERT_EQUAL(memcmp(opt->raw_value.data, "eth0", 4), 0);
        }
    }
    CU_ASSERT_TRUE(saw_relay_msg_option);
    CU_ASSERT_TRUE(saw_interface_id_option);

    cf_dhcpv6_event_free(ev);
}

/* ---- v6_vendor_opts ----------------------------------------------------------- */

static void test_v6_vendor_opts(void)
{
    const char *event_type = NULL;
    Cloudflow__V1__DhcpV6PacketEvent *ev = load_fixture("v6_vendor_opts", &event_type, NULL);

    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);
    CU_ASSERT_STRING_EQUAL(event_type, "dhcpv6.information-request.observed");
    CU_ASSERT_EQUAL(ev->header->message_type,
                     CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__INFORMATION_REQUEST);

    CU_ASSERT_PTR_NOT_NULL_FATAL(ev->decoded->vendor_options);
    CU_ASSERT_EQUAL(ev->decoded->vendor_options->enterprise_number, 99999u);
    CU_ASSERT_EQUAL(ev->decoded->vendor_options->n_suboptions, 2);
    if (ev->decoded->vendor_options->n_suboptions == 2) {
        Cloudflow__V1__DhcpV6VendorSuboption *s0 = ev->decoded->vendor_options->suboptions[0];
        Cloudflow__V1__DhcpV6VendorSuboption *s1 = ev->decoded->vendor_options->suboptions[1];

        CU_ASSERT_EQUAL(s0->code, 1);
        CU_ASSERT_STRING_EQUAL(s0->decoded_value, "cloudflow-fixture");

        CU_ASSERT_EQUAL(s1->code, 2);
        CU_ASSERT_STRING_EQUAL(s1->decoded_value, "deadbeef");
    }

    cf_dhcpv6_event_free(ev);
}

/* ---- v6_malformed_optlen ----------------------------------------------------- */

static void test_v6_malformed_optlen(void)
{
    const char *event_type = NULL;
    Cloudflow__V1__DhcpV6PacketEvent *ev = load_fixture("v6_malformed_optlen", &event_type, NULL);
    size_t i;
    int saw_overrun_warning = 0;

    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);
    CU_ASSERT_STRING_EQUAL(event_type, "dhcpv6.solicit.observed");
    CU_ASSERT_EQUAL(ev->header->message_type, CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__SOLICIT);

    expect_duid_ll(&ev->decoded->client_duid, V6_CLIENT_MAC);

    CU_ASSERT_TRUE(ev->n_parser_warnings > 0);
    for (i = 0; i < ev->n_parser_warnings; i++) {
        if (strcmp(ev->parser_warnings[i]->code, "opt_len_overrun") == 0)
            saw_overrun_warning = 1;
    }
    CU_ASSERT_TRUE(saw_overrun_warning);

    CU_ASSERT_TRUE(ev->n_raw_options > 0);
    if (ev->n_raw_options > 0) {
        Cloudflow__V1__DhcpV6Option *last = ev->raw_options[ev->n_raw_options - 1];
        CU_ASSERT_EQUAL(last->code, 6);
        CU_ASSERT_TRUE(last->malformed);
        CU_ASSERT_EQUAL(last->length, 1);
    }

    cf_dhcpv6_event_free(ev);
}

/* ---- non-fixture tests: paths no single fixture exercises ------------------ */

static void test_too_short_payload_returns_null(void)
{
    uint8_t buf[4] = {1, 0x10, 0x10, 0x10};
    const char *event_type = (const char *)0x1; /* sentinel, must become NULL */
    Cloudflow__V1__DhcpV6PacketEvent *ev;

    ev = cf_dhcpv6_parse(buf, 3, &event_type); /* one byte short of the 4-byte header */
    CU_ASSERT_PTR_NULL(ev);
    CU_ASSERT_PTR_NULL(event_type);

    ev = cf_dhcpv6_parse(buf, 0, &event_type);
    CU_ASSERT_PTR_NULL(ev);

    ev = cf_dhcpv6_parse(NULL, 0, &event_type);
    CU_ASSERT_PTR_NULL(ev);

    /* Exactly the 4-byte header (msg-type + transaction-id), no options,
     * must still parse -- an empty options area is legal. */
    ev = cf_dhcpv6_parse(buf, sizeof(buf), &event_type);
    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);
    CU_ASSERT_STRING_EQUAL(event_type, "dhcpv6.solicit.observed");
    CU_ASSERT_EQUAL(ev->n_raw_options, 0);
    cf_dhcpv6_event_free(ev);
}

static void test_unknown_message_type_is_generic(void)
{
    uint8_t buf[4] = {200, 0, 0, 0}; /* 200 is not an assigned DHCPv6 msg-type */
    const char *event_type = NULL;
    Cloudflow__V1__DhcpV6PacketEvent *ev = cf_dhcpv6_parse(buf, sizeof(buf), &event_type);

    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);
    CU_ASSERT_STRING_EQUAL(event_type, "dhcpv6.packet.observed");
    CU_ASSERT_EQUAL(ev->header->message_type,
                     CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__MESSAGE_TYPE_UNSPECIFIED);

    cf_dhcpv6_event_free(ev);
}

/* A RELAY-FORW/RELAY-REPL header truncated past the 4-byte minimum (e.g.
 * only part of link_address present) must still parse, leaving the
 * unavailable address fields at their proto3 default "". */
static void test_relay_header_truncated_past_minimum(void)
{
    uint8_t buf[10];
    const char *event_type = NULL;
    Cloudflow__V1__DhcpV6PacketEvent *ev;

    memset(buf, 0, sizeof(buf));
    buf[0] = 12; /* RELAY-FORW */
    buf[1] = 3;  /* hop_count */

    ev = cf_dhcpv6_parse(buf, sizeof(buf), &event_type);
    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);
    CU_ASSERT_STRING_EQUAL(event_type, "dhcpv6.relay-forw.observed");
    CU_ASSERT_EQUAL(ev->header->hop_count, 3);
    CU_ASSERT_STRING_EQUAL(ev->header->link_address, "");
    CU_ASSERT_STRING_EQUAL(ev->header->peer_address, "");
    CU_ASSERT_EQUAL(ev->header->transaction_id, 0);

    cf_dhcpv6_event_free(ev);
}

/* Malformed input, in every flavor this parser is asked to survive, must
 * never crash: truncate an otherwise-valid rich payload at every possible
 * length and bit-flip every byte of it once. Reuses the shape of
 * cf_dhcpv4_test.c's equivalent sweep. */
static void test_never_crashes_on_truncation_or_bitflips(void)
{
    uint8_t buf[200];
    size_t total = 0;
    size_t len;

    /* SOLICIT, xid=0xEEEEEE */
    buf[total++] = 1;
    buf[total++] = 0xEE;
    buf[total++] = 0xEE;
    buf[total++] = 0xEE;

    /* OPTION_CLIENTID (1), a DUID-LL-shaped 10-byte value */
    buf[total++] = 0x00;
    buf[total++] = 0x01;
    buf[total++] = 0x00;
    buf[total++] = 0x0a;
    buf[total++] = 0x00;
    buf[total++] = 0x03;
    buf[total++] = 0x00;
    buf[total++] = 0x01;
    buf[total++] = 0x02;
    buf[total++] = 0x00;
    buf[total++] = 0x5e;
    buf[total++] = 0x30;
    buf[total++] = 0x00;
    buf[total++] = 0x01;

    /* OPTION_IA_NA (3), 12-byte header + one nested IAADDR (5) suboption,
     * deliberately truncatable at many interesting offsets. */
    buf[total++] = 0x00;
    buf[total++] = 0x03;
    buf[total++] = 0x00;
    buf[total++] = 0x28; /* len=40: 12-byte IA header + 4+24-byte IAADDR */
    buf[total++] = 0x00;
    buf[total++] = 0x00;
    buf[total++] = 0x00;
    buf[total++] = 0x01; /* IAID */
    buf[total++] = 0x00;
    buf[total++] = 0x00;
    buf[total++] = 0x07;
    buf[total++] = 0x08; /* T1 */
    buf[total++] = 0x00;
    buf[total++] = 0x00;
    buf[total++] = 0x0b;
    buf[total++] = 0x40; /* T2 */
    buf[total++] = 0x00;
    buf[total++] = 0x05;
    buf[total++] = 0x00;
    buf[total++] = 0x18; /* IAADDR, len=24 */
    /* 16-byte address 2001:db8::50 */
    buf[total++] = 0x20;
    buf[total++] = 0x01;
    buf[total++] = 0x0d;
    buf[total++] = 0xb8;
    buf[total++] = 0x00;
    buf[total++] = 0x00;
    buf[total++] = 0x00;
    buf[total++] = 0x00;
    buf[total++] = 0x00;
    buf[total++] = 0x00;
    buf[total++] = 0x00;
    buf[total++] = 0x00;
    buf[total++] = 0x00;
    buf[total++] = 0x00;
    buf[total++] = 0x00;
    buf[total++] = 0x50;
    buf[total++] = 0x00;
    buf[total++] = 0x00;
    buf[total++] = 0x0e;
    buf[total++] = 0x10; /* preferred lifetime */
    buf[total++] = 0x00;
    buf[total++] = 0x00;
    buf[total++] = 0x1c;
    buf[total++] = 0x20; /* valid lifetime */

    /* OPTION_VENDOR_OPTS (17): enterprise + one suboption */
    buf[total++] = 0x00;
    buf[total++] = 0x11;
    buf[total++] = 0x00;
    buf[total++] = 0x0a; /* len=10 */
    buf[total++] = 0x00;
    buf[total++] = 0x00;
    buf[total++] = 0x86;
    buf[total++] = 0x9f; /* enterprise number */
    buf[total++] = 0x00;
    buf[total++] = 0x01;
    buf[total++] = 0x00;
    buf[total++] = 0x02;
    buf[total++] = 'a';
    buf[total++] = 'b';

    for (len = 0; len <= total; len++) {
        const char *et = NULL;
        Cloudflow__V1__DhcpV6PacketEvent *ev = cf_dhcpv6_parse(buf, len, &et);
        if (ev)
            cf_dhcpv6_event_free(ev);
    }

    for (size_t i = 0; i < total; i++) {
        uint8_t saved = buf[i];
        for (int bit = 0; bit < 8; bit++) {
            const char *et = NULL;
            Cloudflow__V1__DhcpV6PacketEvent *ev;
            buf[i] = (uint8_t)(saved ^ (1u << bit));
            ev = cf_dhcpv6_parse(buf, total, &et);
            if (ev)
                cf_dhcpv6_event_free(ev);
        }
        buf[i] = saved;
    }

    CU_PASS("no crash across truncation sweep and single-bit-flip sweep");
}

/* ---- driver ---------------------------------------------------------------- */

int main(void)
{
    CU_pSuite suite;
    unsigned int failed;

    if (CU_initialize_registry() != CUE_SUCCESS)
        return (int)CU_get_error();

    suite = CU_add_suite("cf_dhcpv6", NULL, NULL);
    if (!suite) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    if (!CU_add_test(suite, "v6_solicit", test_v6_solicit) ||
        !CU_add_test(suite, "v6_advertise", test_v6_advertise) ||
        !CU_add_test(suite, "v6_request", test_v6_request) ||
        !CU_add_test(suite, "v6_reply", test_v6_reply) ||
        !CU_add_test(suite, "v6_relay_forw", test_v6_relay_forw) ||
        !CU_add_test(suite, "v6_vendor_opts", test_v6_vendor_opts) ||
        !CU_add_test(suite, "v6_malformed_optlen", test_v6_malformed_optlen) ||
        !CU_add_test(suite, "too-short payload -> NULL; exact-header -> parses",
                      test_too_short_payload_returns_null) ||
        !CU_add_test(suite, "unknown message type -> dhcpv6.packet.observed",
                      test_unknown_message_type_is_generic) ||
        !CU_add_test(suite, "relay header truncated past the 4-byte minimum",
                      test_relay_header_truncated_past_minimum) ||
        !CU_add_test(suite, "never crashes: truncation + bit-flip sweep",
                      test_never_crashes_on_truncation_or_bitflips)) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();

    failed = CU_get_number_of_tests_failed();

    CU_cleanup_registry();

    return failed > 0 ? 1 : 0;
}
