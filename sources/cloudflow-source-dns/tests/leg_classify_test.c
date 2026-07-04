/* CUnit tests for the WP-DNS05 DNS leg classifier (src/leg_classify.c),
 * implementing DNS-D7 in docs/dns-source.md. Pure: no sockets, no packets --
 * every case is a hand-built endpoint tuple plus configured address sets.
 *
 * Addresses use documentation space only: RFC 5737 (192.0.2.0/24,
 * 198.51.100.0/24, 203.0.113.0/24) for IPv4 and RFC 3849 (2001:db8::/32) for
 * IPv6. Follows the registry/main pattern of tests/unit/cf_dns_test.c.
 */

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

#include "leg_classify.h"

/* An ephemeral client source port for the query direction. */
#define EPHEMERAL 40000

/* Fills a 16-byte cloudflow-packet address buffer from a literal, returning
 * the ip_version (4 or 6). Aborts the test on a malformed literal. */
static uint8_t make_ip(const char *lit, uint8_t out[16])
{
    memset(out, 0, 16);
    if (inet_pton(AF_INET, lit, out) == 1)
        return 4;
    if (inet_pton(AF_INET6, lit, out) == 1)
        return 6;
    CU_FAIL_FATAL("test bug: malformed IP literal");
    return 0;
}

/* ---- address-set API ------------------------------------------------------ */

static void test_addr_set_str_add_and_contains(void)
{
    cf_dns_addr_set_t *s = cf_dns_addr_set_new();
    uint8_t v4[16], v6[16], other[16];
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);

    /* good literals accepted */
    CU_ASSERT_EQUAL(cf_dns_addr_set_add_str(s, "192.0.2.10"), 1);
    CU_ASSERT_EQUAL(cf_dns_addr_set_add_str(s, "2001:db8::10"), 1);
    /* malformed literals rejected, set unchanged */
    CU_ASSERT_EQUAL(cf_dns_addr_set_add_str(s, "not-an-ip"), 0);
    CU_ASSERT_EQUAL(cf_dns_addr_set_add_str(s, "192.0.2.256"), 0);
    CU_ASSERT_EQUAL(cf_dns_addr_set_add_str(s, "192.0.2.1/24"), 0);
    CU_ASSERT_EQUAL(cf_dns_addr_set_add_str(s, ""), 0);

    make_ip("192.0.2.10", v4);
    make_ip("2001:db8::10", v6);
    make_ip("192.0.2.11", other);

    CU_ASSERT_EQUAL(cf_dns_addr_set_contains(s, 4, v4), 1);
    CU_ASSERT_EQUAL(cf_dns_addr_set_contains(s, 6, v6), 1);
    /* an address that was never added is not a member */
    CU_ASSERT_EQUAL(cf_dns_addr_set_contains(s, 4, other), 0);

    cf_dns_addr_set_free(s);
}

static void test_addr_set_v4_v6_isolation(void)
{
    cf_dns_addr_set_t *s = cf_dns_addr_set_new();
    uint8_t bytes[16];
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);

    /* Store an all-zero-tail 4-byte pattern as a v4 address. The identical
     * first four bytes queried as v6 must NOT match: matching is version
     * aware. */
    memset(bytes, 0, sizeof(bytes));
    bytes[0] = 192; bytes[1] = 0; bytes[2] = 2; bytes[3] = 1;
    cf_dns_addr_set_add_ip(s, 4, bytes);

    CU_ASSERT_EQUAL(cf_dns_addr_set_contains(s, 4, bytes), 1);
    CU_ASSERT_EQUAL(cf_dns_addr_set_contains(s, 6, bytes), 0);

    cf_dns_addr_set_free(s);
}

static void test_addr_set_add_ip_bytes(void)
{
    cf_dns_addr_set_t *s = cf_dns_addr_set_new();
    uint8_t ip[16], probe[16];
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);

    make_ip("198.51.100.5", ip);
    cf_dns_addr_set_add_ip(s, 4, ip);
    make_ip("198.51.100.5", probe);
    CU_ASSERT_EQUAL(cf_dns_addr_set_contains(s, 4, probe), 1);

    /* an unknown/invalid version is ignored (no crash, not a member) */
    cf_dns_addr_set_add_ip(s, 7, ip);
    CU_ASSERT_EQUAL(cf_dns_addr_set_contains(s, 7, ip), 0);

    /* NULL set is safely empty */
    CU_ASSERT_EQUAL(cf_dns_addr_set_contains(NULL, 4, probe), 0);

    cf_dns_addr_set_free(s);
    cf_dns_addr_set_free(NULL); /* NULL free is a no-op */
}

static void test_addr_set_growth(void)
{
    /* Add more than the initial capacity (8) to exercise the realloc path and
     * confirm every entry is still found (ASan checks the alloc is clean). */
    cf_dns_addr_set_t *s = cf_dns_addr_set_new();
    char lit[32];
    uint8_t probe[16];
    int i;
    CU_ASSERT_PTR_NOT_NULL_FATAL(s);

    for (i = 0; i < 50; i++) {
        snprintf(lit, sizeof(lit), "192.0.2.%d", i);
        CU_ASSERT_EQUAL(cf_dns_addr_set_add_str(s, lit), 1);
    }
    for (i = 0; i < 50; i++) {
        snprintf(lit, sizeof(lit), "192.0.2.%d", i);
        make_ip(lit, probe);
        CU_ASSERT_EQUAL(cf_dns_addr_set_contains(s, 4, probe), 1);
    }
    cf_dns_addr_set_free(s);
}

/* ---- role map (WP-DNS11a) -------------------------------------------------- */

static void test_role_map_build_and_lookup(void)
{
    cf_dns_role_map_t *m = cf_dns_role_map_new();
    uint8_t v4[16], v6[16], other[16];
    const char *label;
    CU_ASSERT_PTR_NOT_NULL_FATAL(m);

    /* good literals mapped to labels */
    CU_ASSERT_EQUAL(cf_dns_role_map_add_str(m, "192.0.2.53", "dnsdist"), 1);
    CU_ASSERT_EQUAL(cf_dns_role_map_add_str(m, "192.0.2.54", "recursor"), 1);
    CU_ASSERT_EQUAL(cf_dns_role_map_add_str(m, "2001:db8::53", "authoritative"), 1);

    /* malformed address / empty-or-NULL label rejected, map unchanged */
    CU_ASSERT_EQUAL(cf_dns_role_map_add_str(m, "not-an-ip", "x"), 0);
    CU_ASSERT_EQUAL(cf_dns_role_map_add_str(m, "192.0.2.60", ""), 0);
    CU_ASSERT_EQUAL(cf_dns_role_map_add_str(m, "192.0.2.60", NULL), 0);

    make_ip("192.0.2.53", v4);
    make_ip("2001:db8::53", v6);
    make_ip("192.0.2.99", other);

    label = cf_dns_role_lookup(m, 4, v4);
    CU_ASSERT_PTR_NOT_NULL_FATAL(label);
    CU_ASSERT_STRING_EQUAL(label, "dnsdist");

    label = cf_dns_role_lookup(m, 6, v6);
    CU_ASSERT_PTR_NOT_NULL_FATAL(label);
    CU_ASSERT_STRING_EQUAL(label, "authoritative");

    /* an address that was never mapped returns NULL */
    CU_ASSERT_PTR_NULL(cf_dns_role_lookup(m, 4, other));

    cf_dns_role_map_free(m);
}

static void test_role_map_v4_v6_isolation(void)
{
    cf_dns_role_map_t *m = cf_dns_role_map_new();
    uint8_t bytes[16];
    CU_ASSERT_PTR_NOT_NULL_FATAL(m);

    /* Same first-4-byte pattern stored as v4 must not match when queried v6. */
    memset(bytes, 0, sizeof(bytes));
    bytes[0] = 192; bytes[1] = 0; bytes[2] = 2; bytes[3] = 53;
    cf_dns_role_map_add_ip(m, 4, bytes, "recursor");

    CU_ASSERT_PTR_NOT_NULL(cf_dns_role_lookup(m, 4, bytes));
    CU_ASSERT_STRING_EQUAL(cf_dns_role_lookup(m, 4, bytes), "recursor");
    CU_ASSERT_PTR_NULL(cf_dns_role_lookup(m, 6, bytes));

    cf_dns_role_map_free(m);
}

static void test_role_map_first_match_and_edges(void)
{
    cf_dns_role_map_t *m = cf_dns_role_map_new();
    uint8_t ip[16];
    int i;
    char lit[32];
    CU_ASSERT_PTR_NOT_NULL_FATAL(m);

    /* First mapping for an address wins over a later duplicate. */
    CU_ASSERT_EQUAL(cf_dns_role_map_add_str(m, "192.0.2.53", "first"), 1);
    CU_ASSERT_EQUAL(cf_dns_role_map_add_str(m, "192.0.2.53", "second"), 1);
    make_ip("192.0.2.53", ip);
    CU_ASSERT_STRING_EQUAL(cf_dns_role_lookup(m, 4, ip), "first");

    /* Grow past the initial capacity (8) to exercise realloc under ASan. */
    for (i = 0; i < 40; i++) {
        snprintf(lit, sizeof(lit), "198.51.100.%d", i);
        CU_ASSERT_EQUAL(cf_dns_role_map_add_str(m, lit, "bulk"), 1);
    }
    for (i = 0; i < 40; i++) {
        snprintf(lit, sizeof(lit), "198.51.100.%d", i);
        make_ip(lit, ip);
        CU_ASSERT_STRING_EQUAL(cf_dns_role_lookup(m, 4, ip), "bulk");
    }

    /* invalid version ignored; NULL map / NULL free safe */
    cf_dns_role_map_add_ip(m, 7, ip, "x");
    CU_ASSERT_PTR_NULL(cf_dns_role_lookup(m, 7, ip));
    CU_ASSERT_PTR_NULL(cf_dns_role_lookup(NULL, 4, ip));

    cf_dns_role_map_free(m);
    cf_dns_role_map_free(NULL); /* no-op */
}

/* ---- classifier: CLIENT_FACING (local server on :53) ---------------------- */

static void test_client_facing_query_and_response(void)
{
    cf_dns_addr_set_t *local = cf_dns_addr_set_new();
    cf_dns_addr_set_t *backend = cf_dns_addr_set_new();
    cf_dns_leg_config_t cfg = { local, backend };
    uint8_t server[16], client[16];
    uint8_t v;
    Cloudflow__V1__DnsLeg leg;
    int lis;
    CU_ASSERT_PTR_NOT_NULL_FATAL(local);
    CU_ASSERT_PTR_NOT_NULL_FATAL(backend);

    cf_dns_addr_set_add_str(local, "192.0.2.53");   /* our local resolver */
    v = make_ip("192.0.2.53", server);
    make_ip("198.51.100.20", client);

    /* query: client(ephemeral) -> server(:53) */
    lis = -1;
    leg = cf_dns_classify_leg(&cfg, v, client, EPHEMERAL, server, 53,
                              CF_DNS_DIR_INGRESS, &lis);
    CU_ASSERT_EQUAL(leg, CLOUDFLOW__V1__DNS_LEG__DNS_LEG_CLIENT_FACING);
    CU_ASSERT_EQUAL(lis, 1);

    /* response: server(:53) -> client(ephemeral) -- endpoints swapped */
    lis = -1;
    leg = cf_dns_classify_leg(&cfg, v, server, 53, client, EPHEMERAL,
                              CF_DNS_DIR_EGRESS, &lis);
    CU_ASSERT_EQUAL(leg, CLOUDFLOW__V1__DNS_LEG__DNS_LEG_CLIENT_FACING);
    CU_ASSERT_EQUAL(lis, 1);

    cf_dns_addr_set_free(local);
    cf_dns_addr_set_free(backend);
}

static void test_client_facing_ipv6(void)
{
    cf_dns_addr_set_t *local = cf_dns_addr_set_new();
    cf_dns_leg_config_t cfg = { local, NULL };
    uint8_t server[16], client[16];
    uint8_t v;
    Cloudflow__V1__DnsLeg leg;
    int lis = -1;
    CU_ASSERT_PTR_NOT_NULL_FATAL(local);

    cf_dns_addr_set_add_str(local, "2001:db8::53");
    v = make_ip("2001:db8::53", server);
    make_ip("2001:db8:1::20", client);

    leg = cf_dns_classify_leg(&cfg, v, client, EPHEMERAL, server, 53,
                              CF_DNS_DIR_INGRESS, &lis);
    CU_ASSERT_EQUAL(leg, CLOUDFLOW__V1__DNS_LEG__DNS_LEG_CLIENT_FACING);
    CU_ASSERT_EQUAL(lis, 1);

    cf_dns_addr_set_free(local);
}

/* ---- classifier: BACKEND (remote :53 in the backend set) ------------------ */

static void test_backend(void)
{
    cf_dns_addr_set_t *local = cf_dns_addr_set_new();
    cf_dns_addr_set_t *backend = cf_dns_addr_set_new();
    cf_dns_leg_config_t cfg = { local, backend };
    uint8_t server[16], us[16];
    uint8_t v;
    Cloudflow__V1__DnsLeg leg;
    int lis = -1;
    CU_ASSERT_PTR_NOT_NULL_FATAL(local);
    CU_ASSERT_PTR_NOT_NULL_FATAL(backend);

    cf_dns_addr_set_add_str(local, "192.0.2.53");     /* dnsdist front */
    cf_dns_addr_set_add_str(backend, "203.0.113.10"); /* pdns backend */
    v = make_ip("203.0.113.10", server);
    make_ip("192.0.2.53", us);

    /* us(ephemeral) -> backend(:53): dnsdist querying pdns */
    leg = cf_dns_classify_leg(&cfg, v, us, EPHEMERAL, server, 53,
                              CF_DNS_DIR_EGRESS, &lis);
    CU_ASSERT_EQUAL(leg, CLOUDFLOW__V1__DNS_LEG__DNS_LEG_BACKEND);
    CU_ASSERT_EQUAL(lis, 0);

    cf_dns_addr_set_free(local);
    cf_dns_addr_set_free(backend);
}

/* ---- classifier: RECURSION_UPSTREAM (remote :53 not in backend set) -------- */

static void test_recursion_upstream(void)
{
    cf_dns_addr_set_t *local = cf_dns_addr_set_new();
    cf_dns_addr_set_t *backend = cf_dns_addr_set_new();
    cf_dns_leg_config_t cfg = { local, backend };
    uint8_t server[16], us[16];
    uint8_t v;
    Cloudflow__V1__DnsLeg leg;
    int lis = -1;
    CU_ASSERT_PTR_NOT_NULL_FATAL(local);
    CU_ASSERT_PTR_NOT_NULL_FATAL(backend);

    cf_dns_addr_set_add_str(local, "192.0.2.53");
    cf_dns_addr_set_add_str(backend, "203.0.113.10");
    /* upstream authoritative not in either set */
    v = make_ip("198.51.100.200", server);
    make_ip("192.0.2.53", us);

    leg = cf_dns_classify_leg(&cfg, v, us, EPHEMERAL, server, 53,
                              CF_DNS_DIR_EGRESS, &lis);
    CU_ASSERT_EQUAL(leg, CLOUDFLOW__V1__DNS_LEG__DNS_LEG_RECURSION_UPSTREAM);
    CU_ASSERT_EQUAL(lis, 0);

    cf_dns_addr_set_free(local);
    cf_dns_addr_set_free(backend);
}

static void test_recursion_upstream_ipv6(void)
{
    cf_dns_addr_set_t *local = cf_dns_addr_set_new();
    cf_dns_addr_set_t *backend = cf_dns_addr_set_new();
    cf_dns_leg_config_t cfg = { local, backend };
    uint8_t server[16], us[16];
    uint8_t v;
    Cloudflow__V1__DnsLeg leg;
    int lis = -1;
    CU_ASSERT_PTR_NOT_NULL_FATAL(local);
    CU_ASSERT_PTR_NOT_NULL_FATAL(backend);

    cf_dns_addr_set_add_str(local, "2001:db8::53");
    v = make_ip("2001:db8:cafe::1", server); /* remote, not local/backend */
    make_ip("2001:db8::53", us);

    leg = cf_dns_classify_leg(&cfg, v, us, EPHEMERAL, server, 53,
                              CF_DNS_DIR_EGRESS, &lis);
    CU_ASSERT_EQUAL(leg, CLOUDFLOW__V1__DNS_LEG__DNS_LEG_RECURSION_UPSTREAM);
    CU_ASSERT_EQUAL(lis, 0);

    cf_dns_addr_set_free(local);
    cf_dns_addr_set_free(backend);
}

/* ---- classifier: UNKNOWN (server side indeterminate) ---------------------- */

static void test_unknown_neither_port_53(void)
{
    cf_dns_addr_set_t *local = cf_dns_addr_set_new();
    cf_dns_leg_config_t cfg = { local, NULL };
    uint8_t a[16], b[16];
    uint8_t v;
    Cloudflow__V1__DnsLeg leg;
    int lis = -1;
    CU_ASSERT_PTR_NOT_NULL_FATAL(local);

    cf_dns_addr_set_add_str(local, "192.0.2.53");
    v = make_ip("192.0.2.53", a);
    make_ip("198.51.100.20", b);

    /* neither endpoint on :53 -> indeterminate server side */
    leg = cf_dns_classify_leg(&cfg, v, a, 4444, b, 5555,
                              CF_DNS_DIR_UNKNOWN, &lis);
    CU_ASSERT_EQUAL(leg, CLOUDFLOW__V1__DNS_LEG__DNS_LEG_UNKNOWN);
    CU_ASSERT_EQUAL(lis, 0);

    cf_dns_addr_set_free(local);
}

static void test_unknown_both_port_53(void)
{
    cf_dns_addr_set_t *local = cf_dns_addr_set_new();
    cf_dns_leg_config_t cfg = { local, NULL };
    uint8_t a[16], b[16];
    uint8_t v;
    Cloudflow__V1__DnsLeg leg;
    int lis = -1;
    CU_ASSERT_PTR_NOT_NULL_FATAL(local);

    cf_dns_addr_set_add_str(local, "192.0.2.53");
    v = make_ip("192.0.2.53", a);
    make_ip("203.0.113.10", b);

    /* both endpoints on :53 (server-to-server on 53) -> indeterminate */
    leg = cf_dns_classify_leg(&cfg, v, a, 53, b, 53,
                              CF_DNS_DIR_UNKNOWN, &lis);
    CU_ASSERT_EQUAL(leg, CLOUDFLOW__V1__DNS_LEG__DNS_LEG_UNKNOWN);
    CU_ASSERT_EQUAL(lis, 0);

    cf_dns_addr_set_free(local);
}

/* ---- capture direction is a cross-check only, never an override ----------- */

/* DNS-D7 step 3: capture direction may only confirm/tie-break, never override
 * an authoritative address-set decision. The same authoritative CLIENT_FACING
 * packet must classify identically regardless of the direction reported by the
 * ring -- INGRESS, EGRESS, or UNKNOWN (the SPAN/mirror case). This is the case
 * where direction is the *only* differing input; it must NOT change the role. */
static void test_direction_never_overrides(void)
{
    cf_dns_addr_set_t *local = cf_dns_addr_set_new();
    cf_dns_leg_config_t cfg = { local, NULL };
    uint8_t server[16], client[16];
    uint8_t v;
    int lis_i = -1, lis_e = -1, lis_u = -1;
    Cloudflow__V1__DnsLeg leg_i, leg_e, leg_u;
    CU_ASSERT_PTR_NOT_NULL_FATAL(local);

    cf_dns_addr_set_add_str(local, "192.0.2.53");
    v = make_ip("192.0.2.53", server);
    make_ip("198.51.100.20", client);

    /* Identical query tuple, three different capture directions. Even the
     * "wrong" direction for a client-facing query (EGRESS) must not flip the
     * authoritative address-set decision. */
    leg_i = cf_dns_classify_leg(&cfg, v, client, EPHEMERAL, server, 53,
                                CF_DNS_DIR_INGRESS, &lis_i);
    leg_e = cf_dns_classify_leg(&cfg, v, client, EPHEMERAL, server, 53,
                                CF_DNS_DIR_EGRESS, &lis_e);
    leg_u = cf_dns_classify_leg(&cfg, v, client, EPHEMERAL, server, 53,
                                CF_DNS_DIR_UNKNOWN, &lis_u);

    CU_ASSERT_EQUAL(leg_i, CLOUDFLOW__V1__DNS_LEG__DNS_LEG_CLIENT_FACING);
    CU_ASSERT_EQUAL(leg_e, CLOUDFLOW__V1__DNS_LEG__DNS_LEG_CLIENT_FACING);
    CU_ASSERT_EQUAL(leg_u, CLOUDFLOW__V1__DNS_LEG__DNS_LEG_CLIENT_FACING);
    CU_ASSERT_EQUAL(lis_i, 1);
    CU_ASSERT_EQUAL(lis_e, 1);
    CU_ASSERT_EQUAL(lis_u, 1);

    cf_dns_addr_set_free(local);
}

/* NULL config / empty sets: with no local or backend addresses, a remote :53
 * is RECURSION_UPSTREAM and local_is_server_out may be NULL safely. */
static void test_null_config_and_out(void)
{
    uint8_t server[16], client[16];
    uint8_t v;
    Cloudflow__V1__DnsLeg leg;

    v = make_ip("198.51.100.200", server);
    make_ip("192.0.2.20", client);

    /* NULL cfg -> empty sets -> remote :53 -> RECURSION_UPSTREAM, NULL out ok */
    leg = cf_dns_classify_leg(NULL, v, client, EPHEMERAL, server, 53,
                              CF_DNS_DIR_UNKNOWN, NULL);
    CU_ASSERT_EQUAL(leg, CLOUDFLOW__V1__DNS_LEG__DNS_LEG_RECURSION_UPSTREAM);
}

/* ---- driver --------------------------------------------------------------- */

int main(void)
{
    CU_pSuite suite;
    unsigned int failed;

    if (CU_initialize_registry() != CUE_SUCCESS)
        return (int)CU_get_error();

    suite = CU_add_suite("leg_classify", NULL, NULL);
    if (!suite) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    if (!CU_add_test(suite, "addr set: str add + contains", test_addr_set_str_add_and_contains) ||
        !CU_add_test(suite, "addr set: v4/v6 isolation", test_addr_set_v4_v6_isolation) ||
        !CU_add_test(suite, "addr set: add via bytes + edge cases", test_addr_set_add_ip_bytes) ||
        !CU_add_test(suite, "addr set: growth past initial capacity", test_addr_set_growth) ||
        !CU_add_test(suite, "role map: build + lookup", test_role_map_build_and_lookup) ||
        !CU_add_test(suite, "role map: v4/v6 isolation", test_role_map_v4_v6_isolation) ||
        !CU_add_test(suite, "role map: first-match + growth + edges", test_role_map_first_match_and_edges) ||
        !CU_add_test(suite, "CLIENT_FACING query + response", test_client_facing_query_and_response) ||
        !CU_add_test(suite, "CLIENT_FACING IPv6", test_client_facing_ipv6) ||
        !CU_add_test(suite, "BACKEND remote :53 in backend set", test_backend) ||
        !CU_add_test(suite, "RECURSION_UPSTREAM remote :53", test_recursion_upstream) ||
        !CU_add_test(suite, "RECURSION_UPSTREAM IPv6", test_recursion_upstream_ipv6) ||
        !CU_add_test(suite, "UNKNOWN neither port 53", test_unknown_neither_port_53) ||
        !CU_add_test(suite, "UNKNOWN both port 53", test_unknown_both_port_53) ||
        !CU_add_test(suite, "direction never overrides address set", test_direction_never_overrides) ||
        !CU_add_test(suite, "NULL config + NULL out", test_null_config_and_out)) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();

    failed = CU_get_number_of_tests_failed();
    CU_cleanup_registry();
    return failed > 0 ? 1 : 0;
}
