/* CUnit acceptance tests for the WP-06 DHCPv4 parser
 * (libs/cloudflow-packet/cf_dhcpv4*.c). Standalone binary
 * (build/cf_dhcpv4_test), following the "one binary per WP" pattern
 * documented in tests/unit/Makefile.
 *
 * Fixture-driven tests load a pcap from tests/fixtures/dhcp/ (built by
 * generate_fixtures.py), extract the UDP payload via cf_decap_udp (WP-05),
 * and parse it with cf_dhcpv4_parse, asserting the core fields the
 * fixture's <name>.expected.md documents. A handful of additional tests
 * build DHCP payloads directly (the same hand-built-byte-array style as
 * cf_decap_test.c) to cover parser paths no single fixture exercises on
 * its own (the too-short-header rejection, the ASCII/E=0 FQDN encoding,
 * and the "rebind" half of the renewal/rebind heuristic).
 */

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cf_decap.h"
#include "cf_dhcpv4.h"

#ifndef FIXTURES_DIR
#define FIXTURES_DIR "../fixtures/dhcp"
#endif

/* ---- tiny classic-pcap reader --------------------------------------------
 *
 * Every fixture is a single-packet classic (not nanosecond, though this
 * reads either) pcap file. This reads just the first packet's captured
 * bytes -- the raw Ethernet frame -- honoring the file's declared byte
 * order, which is all cf_decap_udp() needs.
 */

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

/* Loads a fixture by name, decapsulates it, and parses the DHCPv4 payload.
 * Fails the current CUnit test (via CU_FAIL) and returns NULL on any
 * failure along the way, so callers can just check for NULL. */
static Cloudflow__V1__DhcpV4PacketEvent *load_fixture(const char *name,
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

    return cf_dhcpv4_parse(decap.payload, decap.payload_len, event_type);
}

/* ---- v4_discover ----------------------------------------------------------- */

static void test_v4_discover(void)
{
    const char *event_type = NULL;
    Cloudflow__V1__DhcpV4PacketEvent *ev = load_fixture("v4_discover", &event_type, NULL);

    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);
    CU_ASSERT_STRING_EQUAL(event_type, "dhcpv4.discover.observed");
    CU_ASSERT_STRING_EQUAL(ev->interpretation->event_type, "dhcpv4.discover.observed");

    CU_ASSERT_EQUAL(ev->header->op, 1);
    CU_ASSERT_EQUAL(ev->header->htype, 1);
    CU_ASSERT_EQUAL(ev->header->hlen, 6);
    CU_ASSERT_EQUAL(ev->header->xid, 0x11111111u);
    CU_ASSERT_EQUAL(ev->header->flags, 0x8000u);
    CU_ASSERT_STRING_EQUAL(ev->header->chaddr_mac, "02:00:5e:10:00:01");

    CU_ASSERT_EQUAL(ev->decoded->message_type,
                     CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__DISCOVER);
    CU_ASSERT_STRING_EQUAL(ev->decoded->message_type_name, "DISCOVER");
    CU_ASSERT_EQUAL(ev->decoded->n_parameter_request_list, 4);
    if (ev->decoded->n_parameter_request_list == 4) {
        CU_ASSERT_EQUAL(ev->decoded->parameter_request_list[0], 1);
        CU_ASSERT_EQUAL(ev->decoded->parameter_request_list[1], 3);
        CU_ASSERT_EQUAL(ev->decoded->parameter_request_list[2], 6);
        CU_ASSERT_EQUAL(ev->decoded->parameter_request_list[3], 15);
    }
    CU_ASSERT_EQUAL(ev->decoded->max_dhcp_message_size, 1500);
    CU_ASSERT_STRING_EQUAL(ev->decoded->client_identifier_text, "02:00:5e:10:00:01");

    CU_ASSERT_TRUE(ev->interpretation->is_broadcast);
    CU_ASSERT_FALSE(ev->interpretation->is_relayed);
    CU_ASSERT_STRING_EQUAL(ev->interpretation->normalized_client_key, "0102005e100001");

    CU_ASSERT_EQUAL(ev->n_raw_options, 4); /* 53, 55, 57, 61 (end is not stored) */

    /* pack/unpack round trip */
    {
        size_t plen = cloudflow__v1__dhcp_v4_packet_event__get_packed_size(ev);
        uint8_t *packed = malloc(plen);
        Cloudflow__V1__DhcpV4PacketEvent *rt;

        CU_ASSERT_PTR_NOT_NULL_FATAL(packed);
        CU_ASSERT_EQUAL(cloudflow__v1__dhcp_v4_packet_event__pack(ev, packed), plen);

        rt = cloudflow__v1__dhcp_v4_packet_event__unpack(NULL, plen, packed);
        CU_ASSERT_PTR_NOT_NULL_FATAL(rt);
        CU_ASSERT_STRING_EQUAL(rt->interpretation->event_type, "dhcpv4.discover.observed");
        CU_ASSERT_EQUAL(rt->header->xid, 0x11111111u);
        CU_ASSERT_EQUAL(rt->decoded->message_type,
                         CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__DISCOVER);
        CU_ASSERT_EQUAL(rt->n_raw_options, ev->n_raw_options);

        cloudflow__v1__dhcp_v4_packet_event__free_unpacked(rt, NULL);
        free(packed);
    }

    cf_dhcpv4_event_free(ev);
}

/* ---- v4_offer ---------------------------------------------------------- */

static void test_v4_offer(void)
{
    const char *event_type = NULL;
    Cloudflow__V1__DhcpV4PacketEvent *ev = load_fixture("v4_offer", &event_type, NULL);

    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);
    CU_ASSERT_STRING_EQUAL(event_type, "dhcpv4.offer.observed");

    CU_ASSERT_STRING_EQUAL(ev->decoded->subnet_mask, "255.255.255.0");
    CU_ASSERT_EQUAL(ev->decoded->n_routers, 1);
    if (ev->decoded->n_routers == 1)
        CU_ASSERT_STRING_EQUAL(ev->decoded->routers[0], "192.0.2.1");
    CU_ASSERT_EQUAL(ev->decoded->n_domain_name_servers, 2);
    if (ev->decoded->n_domain_name_servers == 2) {
        CU_ASSERT_STRING_EQUAL(ev->decoded->domain_name_servers[0], "192.0.2.53");
        CU_ASSERT_STRING_EQUAL(ev->decoded->domain_name_servers[1], "198.51.100.53");
    }
    CU_ASSERT_EQUAL(ev->decoded->ip_address_lease_time_seconds, 86400u);
    CU_ASSERT_STRING_EQUAL(ev->decoded->server_identifier, "192.0.2.2");
    CU_ASSERT_EQUAL(ev->decoded->renewal_time_t1_seconds, 43200u);
    CU_ASSERT_EQUAL(ev->decoded->rebinding_time_t2_seconds, 75600u);

    CU_ASSERT_STRING_EQUAL(ev->interpretation->lease_address, "192.0.2.50");

    cf_dhcpv4_event_free(ev);
}

/* ---- v4_request_renewal -------------------------------------------------- */

static void test_v4_request_renewal(void)
{
    const char *event_type = NULL;
    Cloudflow__V1__DhcpV4PacketEvent *ev =
        load_fixture("v4_request_renewal", &event_type, NULL);

    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);
    CU_ASSERT_STRING_EQUAL(event_type, "dhcpv4.request.observed");
    CU_ASSERT_EQUAL(ev->decoded->message_type,
                     CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__REQUEST);

    CU_ASSERT_STRING_EQUAL(ev->decoded->requested_ip_address, "");
    CU_ASSERT_STRING_EQUAL(ev->decoded->server_identifier, "");

    CU_ASSERT_FALSE(ev->interpretation->is_broadcast);
    CU_ASSERT_TRUE(ev->interpretation->is_renewal);
    CU_ASSERT_FALSE(ev->interpretation->is_rebind);

    cf_dhcpv4_event_free(ev);
}

/* ---- v4_ack -------------------------------------------------------------- */

static void test_v4_ack(void)
{
    const char *event_type = NULL;
    Cloudflow__V1__DhcpV4PacketEvent *ev = load_fixture("v4_ack", &event_type, NULL);

    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);
    CU_ASSERT_STRING_EQUAL(event_type, "dhcpv4.ack.observed");

    CU_ASSERT_PTR_NOT_NULL_FATAL(ev->decoded->client_fqdn);
    CU_ASSERT_EQUAL(ev->decoded->client_fqdn->flags, 0x04u);
    CU_ASSERT_STRING_EQUAL(ev->decoded->client_fqdn->domain_name, "client1.example.com");

    CU_ASSERT_EQUAL(ev->decoded->n_domain_search, 2);
    if (ev->decoded->n_domain_search == 2) {
        CU_ASSERT_STRING_EQUAL(ev->decoded->domain_search[0], "eng.example.com");
        CU_ASSERT_STRING_EQUAL(ev->decoded->domain_search[1], "example.com");
    }

    CU_ASSERT_STRING_EQUAL(ev->interpretation->lease_address, "192.0.2.51");

    cf_dhcpv4_event_free(ev);
}

/* ---- v4_nak -------------------------------------------------------------- */

static void test_v4_nak(void)
{
    const char *event_type = NULL;
    Cloudflow__V1__DhcpV4PacketEvent *ev = load_fixture("v4_nak", &event_type, NULL);

    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);
    CU_ASSERT_STRING_EQUAL(event_type, "dhcpv4.nak.observed");
    CU_ASSERT_STRING_EQUAL(ev->decoded->server_identifier, "192.0.2.2");
    CU_ASSERT_STRING_EQUAL(ev->decoded->message,
                            "requested address not available on this subnet");
    CU_ASSERT_STRING_EQUAL(ev->interpretation->lease_address, "");

    cf_dhcpv4_event_free(ev);
}

/* ---- v4_relayed_ack ------------------------------------------------------- */

static void test_v4_relayed_ack(void)
{
    const char *event_type = NULL;
    Cloudflow__V1__DhcpV4PacketEvent *ev =
        load_fixture("v4_relayed_ack", &event_type, NULL);

    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);
    CU_ASSERT_STRING_EQUAL(event_type, "dhcpv4.ack.observed");
    CU_ASSERT_STRING_EQUAL(ev->header->giaddr, "198.51.100.1");
    CU_ASSERT_TRUE(ev->interpretation->is_relayed);

    CU_ASSERT_PTR_NOT_NULL_FATAL(ev->decoded->relay_agent_information);
    CU_ASSERT_STRING_EQUAL(ev->decoded->relay_agent_information->circuit_id, "eth01");
    CU_ASSERT_STRING_EQUAL(ev->decoded->relay_agent_information->remote_id, "02005e10000a");
    CU_ASSERT_STRING_EQUAL(ev->decoded->relay_agent_information->subscriber_id, "sub-001");

    cf_dhcpv4_event_free(ev);
}

/* ---- v4_vlan_discover ------------------------------------------------------ */

static void test_v4_vlan_discover(void)
{
    const char *event_type = NULL;
    cf_decap_udp_t decap;
    Cloudflow__V1__DhcpV4PacketEvent *ev =
        load_fixture("v4_vlan_discover", &event_type, &decap);

    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);
    CU_ASSERT_EQUAL(decap.vlan_count, 1);
    if (decap.vlan_count == 1)
        CU_ASSERT_EQUAL(decap.vlan_ids[0], 100u);

    CU_ASSERT_STRING_EQUAL(event_type, "dhcpv4.discover.observed");
    CU_ASSERT_EQUAL(ev->header->xid, 0x66666666u);
    CU_ASSERT_EQUAL(ev->decoded->message_type,
                     CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__DISCOVER);

    cf_dhcpv4_event_free(ev);
}

/* ---- v4_overload ------------------------------------------------------------ */

static void test_v4_overload(void)
{
    const char *event_type = NULL;
    Cloudflow__V1__DhcpV4PacketEvent *ev = load_fixture("v4_overload", &event_type, NULL);
    int saw_file = 0, saw_sname = 0;
    size_t i;

    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);
    CU_ASSERT_STRING_EQUAL(event_type, "dhcpv4.ack.observed");

    CU_ASSERT_EQUAL(ev->decoded->option_overload, 3u);
    CU_ASSERT_STRING_EQUAL(ev->decoded->subnet_mask, "255.255.255.0");
    CU_ASSERT_EQUAL(ev->decoded->n_routers, 1);
    if (ev->decoded->n_routers == 1)
        CU_ASSERT_STRING_EQUAL(ev->decoded->routers[0], "192.0.2.1");
    CU_ASSERT_EQUAL(ev->decoded->n_domain_name_servers, 1);
    if (ev->decoded->n_domain_name_servers == 1)
        CU_ASSERT_STRING_EQUAL(ev->decoded->domain_name_servers[0], "192.0.2.53");
    CU_ASSERT_STRING_EQUAL(ev->decoded->host_name, "host1");

    CU_ASSERT_STRING_EQUAL(ev->header->sname_text, "");
    CU_ASSERT_STRING_EQUAL(ev->header->file_text, "");

    for (i = 0; i < ev->n_raw_options; i++) {
        if (ev->raw_options[i]->source_field ==
            CLOUDFLOW__V1__DHCP_V4_OPTION__SOURCE_FIELD__SOURCE_FIELD_FILE)
            saw_file = 1;
        if (ev->raw_options[i]->source_field ==
            CLOUDFLOW__V1__DHCP_V4_OPTION__SOURCE_FIELD__SOURCE_FIELD_SNAME)
            saw_sname = 1;
    }
    CU_ASSERT_TRUE(saw_file);
    CU_ASSERT_TRUE(saw_sname);

    cf_dhcpv4_event_free(ev);
}

/* ---- v4_long_option ---------------------------------------------------------- */

static void test_v4_long_option(void)
{
    const char *event_type = NULL;
    Cloudflow__V1__DhcpV4PacketEvent *ev =
        load_fixture("v4_long_option", &event_type, NULL);
    size_t i;
    int code121_count = 0;
    int code121_all_fragments = 1;

    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);
    CU_ASSERT_STRING_EQUAL(event_type, "dhcpv4.ack.observed");

    for (i = 0; i < ev->n_raw_options; i++) {
        if (ev->raw_options[i]->code == 121) {
            code121_count++;
            if (!ev->raw_options[i]->long_option_fragment)
                code121_all_fragments = 0;
        }
    }
    CU_ASSERT_EQUAL(code121_count, 2); /* 360 bytes -> RFC 3396 255 + 105 split */
    CU_ASSERT_TRUE(code121_all_fragments);

    CU_ASSERT_EQUAL(ev->decoded->n_classless_static_routes, 40);
    if (ev->decoded->n_classless_static_routes == 40) {
        CU_ASSERT_EQUAL(ev->decoded->classless_static_routes[0]->destination_prefix_length, 32);
        CU_ASSERT_STRING_EQUAL(ev->decoded->classless_static_routes[0]->destination,
                                "192.0.2.0");
        CU_ASSERT_STRING_EQUAL(ev->decoded->classless_static_routes[0]->router,
                                "198.51.100.1");
        CU_ASSERT_STRING_EQUAL(ev->decoded->classless_static_routes[39]->destination,
                                "192.0.2.39");
        CU_ASSERT_STRING_EQUAL(ev->decoded->classless_static_routes[39]->router,
                                "198.51.100.1");
    }

    cf_dhcpv4_event_free(ev);
}

/* ---- v4_malformed_optlen ------------------------------------------------------ */

static void test_v4_malformed_optlen(void)
{
    const char *event_type = NULL;
    Cloudflow__V1__DhcpV4PacketEvent *ev =
        load_fixture("v4_malformed_optlen", &event_type, NULL);
    size_t i;
    int saw_overrun_warning = 0;

    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);
    CU_ASSERT_STRING_EQUAL(event_type, "dhcpv4.discover.observed");
    CU_ASSERT_EQUAL(ev->decoded->message_type,
                     CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__DISCOVER);

    CU_ASSERT_TRUE(ev->n_parser_warnings > 0);
    for (i = 0; i < ev->n_parser_warnings; i++) {
        if (strcmp(ev->parser_warnings[i]->code, "opt_len_overrun") == 0)
            saw_overrun_warning = 1;
    }
    CU_ASSERT_TRUE(saw_overrun_warning);

    CU_ASSERT_PTR_NOT_NULL_FATAL(ev->n_raw_options > 0 ? ev->raw_options[ev->n_raw_options - 1] : NULL);
    if (ev->n_raw_options > 0) {
        Cloudflow__V1__DhcpV4Option *last = ev->raw_options[ev->n_raw_options - 1];
        CU_ASSERT_EQUAL(last->code, 50);
        CU_ASSERT_TRUE(last->malformed);
    }

    cf_dhcpv4_event_free(ev);
}

/* ---- v4_no_msgtype -------------------------------------------------------- */

static void test_v4_no_msgtype(void)
{
    const char *event_type = NULL;
    Cloudflow__V1__DhcpV4PacketEvent *ev = load_fixture("v4_no_msgtype", &event_type, NULL);

    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);
    CU_ASSERT_STRING_EQUAL(event_type, "dhcpv4.packet.observed");
    CU_ASSERT_EQUAL(ev->decoded->message_type,
                     CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__MESSAGE_TYPE_UNSPECIFIED);
    CU_ASSERT_STRING_EQUAL(ev->decoded->message_type_name, "");

    cf_dhcpv4_event_free(ev);
}

/* ---- non-fixture tests: paths no single fixture exercises ------------------ */

static size_t put_bytes(uint8_t *buf, size_t off, const void *src, size_t n)
{
    memcpy(buf + off, src, n);
    return off + n;
}

static size_t put_u32(uint8_t *buf, size_t off, uint32_t v)
{
    uint8_t b[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
    return put_bytes(buf, off, b, 4);
}

static size_t put_u16(uint8_t *buf, size_t off, uint16_t v)
{
    uint8_t b[2] = {(uint8_t)(v >> 8), (uint8_t)v};
    return put_bytes(buf, off, b, 2);
}

static const uint8_t TEST_MAC[6] = {0x02, 0x00, 0x5e, 0x20, 0x00, 0x01};
static const uint8_t MAGIC[4] = {99, 130, 83, 99};

/* Builds a minimal, well-formed BOOTP fixed header (236 bytes) + magic
 * cookie into `buf`, returning the offset right after the cookie (240) --
 * i.e. where options should be appended. */
static size_t put_fixed_header(uint8_t *buf, uint8_t op, uint32_t xid, uint16_t flags,
                                const uint8_t ciaddr[4])
{
    size_t off = 0;

    memset(buf, 0, 240);
    buf[0] = op;
    buf[1] = 1; /* htype = Ethernet */
    buf[2] = 6; /* hlen */
    buf[3] = 0; /* hops */
    off = put_u32(buf, 4, xid);
    off = put_u16(buf, 8, 0); /* secs */
    off = put_u16(buf, 10, flags);
    off = put_bytes(buf, 12, ciaddr, 4); /* ciaddr */
    /* yiaddr/siaddr/giaddr left zero */
    off = put_bytes(buf, 28, TEST_MAC, 6); /* chaddr */
    off = put_bytes(buf, 236, MAGIC, 4);
    (void)off;
    return 240;
}

static void test_too_short_header_returns_null(void)
{
    uint8_t buf[236]; /* exactly the fixed-header length */
    const char *event_type = (const char *)0x1; /* sentinel, must become NULL */
    Cloudflow__V1__DhcpV4PacketEvent *ev;

    memset(buf, 0, sizeof(buf));

    /* One byte short of the 236-byte fixed header -> NULL. */
    ev = cf_dhcpv4_parse(buf, sizeof(buf) - 1, &event_type);
    CU_ASSERT_PTR_NULL(ev);
    CU_ASSERT_PTR_NULL(event_type);

    /* A header-only payload with no options/cookie must still parse (BOOTP
     * with no magic cookie is legal, if archaic). */
    ev = cf_dhcpv4_parse(buf, sizeof(buf), &event_type);
    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);
    CU_ASSERT_FALSE(ev->header->magic_cookie_present);
    CU_ASSERT_STRING_EQUAL(event_type, "dhcpv4.packet.observed");
    cf_dhcpv4_event_free(ev);
}

static void test_fqdn_ascii_encoding(void)
{
    uint8_t buf[300];
    static const uint8_t zero4[4] = {0, 0, 0, 0};
    size_t pos = put_fixed_header(buf, 2, 0xBBBBBBBBu, 0, zero4);
    const char *domain = "legacy.example.com";
    const char *event_type = NULL;
    Cloudflow__V1__DhcpV4PacketEvent *ev;

    buf[pos++] = 53;
    buf[pos++] = 1;
    buf[pos++] = 5; /* ACK */

    buf[pos++] = 81;
    buf[pos++] = (uint8_t)(3 + strlen(domain));
    buf[pos++] = 0x00; /* flags: E bit clear -> legacy ASCII encoding */
    buf[pos++] = 0x00;
    buf[pos++] = 0x00;
    pos = put_bytes(buf, pos, domain, strlen(domain));

    buf[pos++] = 255;

    ev = cf_dhcpv4_parse(buf, pos, &event_type);
    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);
    CU_ASSERT_PTR_NOT_NULL_FATAL(ev->decoded->client_fqdn);
    CU_ASSERT_EQUAL(ev->decoded->client_fqdn->flags, 0);
    CU_ASSERT_STRING_EQUAL(ev->decoded->client_fqdn->domain_name, domain);

    cf_dhcpv4_event_free(ev);
}

/* REQUEST with no server-id/requested-ip, broadcast flag set -> rebind (the
 * other half of the renewal/rebind heuristic; v4_request_renewal fixture
 * covers the renewal half). */
static void test_rebind_heuristic(void)
{
    uint8_t buf[260];
    static const uint8_t zero4[4] = {0, 0, 0, 0};
    size_t pos = put_fixed_header(buf, 1, 0xCCCCCCCCu, 0x8000, zero4);
    const char *event_type = NULL;
    Cloudflow__V1__DhcpV4PacketEvent *ev;

    buf[pos++] = 53;
    buf[pos++] = 1;
    buf[pos++] = 3; /* REQUEST */
    buf[pos++] = 255;

    ev = cf_dhcpv4_parse(buf, pos, &event_type);
    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);
    CU_ASSERT_TRUE(ev->interpretation->is_broadcast);
    CU_ASSERT_TRUE(ev->interpretation->is_rebind);
    CU_ASSERT_FALSE(ev->interpretation->is_renewal);

    cf_dhcpv4_event_free(ev);
}

/* Malformed input, in every flavor this parser is asked to survive, must
 * never crash: truncate an otherwise-valid rich payload at every possible
 * length and bit-flip every byte of it once. */
static void test_never_crashes_on_truncation_or_bitflips(void)
{
    uint8_t buf[300];
    static const uint8_t zero4[4] = {0, 0, 0, 0};
    size_t total = put_fixed_header(buf, 1, 0xDDDDDDDDu, 0, zero4);
    size_t len;

    buf[total++] = 53;
    buf[total++] = 1;
    buf[total++] = 1;
    buf[total++] = 121; /* classless routes, deliberately short/truncatable */
    buf[total++] = 9;
    buf[total++] = 32;
    buf[total++] = 192;
    buf[total++] = 0;
    buf[total++] = 2;
    buf[total++] = 1;
    buf[total++] = 198;
    buf[total++] = 51;
    buf[total++] = 100;
    buf[total++] = 1;
    buf[total++] = 82;
    buf[total++] = 4;
    buf[total++] = 1;
    buf[total++] = 2;
    buf[total++] = 'a';
    buf[total++] = 'b';
    buf[total++] = 255;

    for (len = 0; len <= total; len++) {
        const char *et = NULL;
        Cloudflow__V1__DhcpV4PacketEvent *ev = cf_dhcpv4_parse(buf, len, &et);
        if (ev)
            cf_dhcpv4_event_free(ev);
    }

    for (size_t i = 0; i < total; i++) {
        uint8_t saved = buf[i];
        for (int bit = 0; bit < 8; bit++) {
            const char *et = NULL;
            Cloudflow__V1__DhcpV4PacketEvent *ev;
            buf[i] = (uint8_t)(saved ^ (1u << bit));
            ev = cf_dhcpv4_parse(buf, total, &et);
            if (ev)
                cf_dhcpv4_event_free(ev);
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

    suite = CU_add_suite("cf_dhcpv4", NULL, NULL);
    if (!suite) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    if (!CU_add_test(suite, "v4_discover", test_v4_discover) ||
        !CU_add_test(suite, "v4_offer", test_v4_offer) ||
        !CU_add_test(suite, "v4_request_renewal", test_v4_request_renewal) ||
        !CU_add_test(suite, "v4_ack", test_v4_ack) ||
        !CU_add_test(suite, "v4_nak", test_v4_nak) ||
        !CU_add_test(suite, "v4_relayed_ack", test_v4_relayed_ack) ||
        !CU_add_test(suite, "v4_vlan_discover", test_v4_vlan_discover) ||
        !CU_add_test(suite, "v4_overload", test_v4_overload) ||
        !CU_add_test(suite, "v4_long_option", test_v4_long_option) ||
        !CU_add_test(suite, "v4_malformed_optlen", test_v4_malformed_optlen) ||
        !CU_add_test(suite, "v4_no_msgtype", test_v4_no_msgtype) ||
        !CU_add_test(suite, "too-short header -> NULL; header-only -> packet.observed",
                      test_too_short_header_returns_null) ||
        !CU_add_test(suite, "FQDN legacy ASCII (E bit clear) encoding",
                      test_fqdn_ascii_encoding) ||
        !CU_add_test(suite, "rebind heuristic (broadcast REQUEST, no server-id/requested-ip)",
                      test_rebind_heuristic) ||
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
