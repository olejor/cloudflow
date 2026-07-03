/* CUnit acceptance tests for WP-10 (the event formatter). Standalone binary
 * (sources/cloudflow-source-dhcp/build/formatter_test), wired into this
 * directory's own Makefile `test`/`test-asan` targets -- tests/unit/ is owned
 * by another WP, per the same convention rx_reader_test.c and
 * libs/cloudflow-redis/tests follow.
 *
 * Each test drives the pure cf_format_packet() with a real frame (loaded from
 * a committed fixture pcap via the tested pcap_replay path, or hand-built for
 * the non-DHCP / oversize cases), then unpacks the produced protobuf payload
 * and asserts on the decoded CloudFlowEvent. FIXTURES_DIR is defined by the
 * Makefile to the absolute tests/fixtures/dhcp path. */

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cf_queue.h"
#include "cf_stats.h"
#include "cloudflow.h"
#include "formatter.h"
#include "pcap_replay.h"
#include "queue_policy.h"
#include "source_stats.h"

#include "cloudflow/v1/envelope.pb-c.h"

#ifndef FIXTURES_DIR
#define FIXTURES_DIR "../../tests/fixtures/dhcp"
#endif

/* ---- helpers ----------------------------------------------------------- */

static formatter_config_t make_cfg(cf_source_stats_t *stats)
{
    formatter_config_t cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.source_host = "dhcp-test-01";
    cfg.source_instance = "inst-a";
    cfg.capture_interface = "eth0";
    cfg.observation_method = "pcap-replay";
    cfg.stats = stats;
    cfg.on_full = CF_ONFULL_DROP_NEWEST;
    return cfg;
}

/* Loads the single frame of a fixture pcap into `out` via the tested
 * pcap_replay_file() path. Returns 0 on success. */
static int load_fixture_frame(const char *name, cf_packet_item_t *out)
{
    char path[512];
    cf_queue_t q;
    cf_source_stats_t st;
    long n;
    int rc = -1;

    memset(&st, 0, sizeof(st));
    snprintf(path, sizeof(path), "%s/%s.pcap", FIXTURES_DIR, name);

    if (cf_queue_init(&q, 8, sizeof(cf_packet_item_t)) != 0)
        return -1;

    n = pcap_replay_file(path, &q, &st, CF_ONFULL_DROP_NEWEST);
    if (n >= 1 && cf_queue_pop(&q, out) == 0)
        rc = 0;

    cf_queue_destroy(&q);
    return rc;
}

/* Formats one packet item and unpacks the resulting payload. On success the
 * caller owns *ev_out and must free it with
 * cloudflow__v1__cloud_flow_event__free_unpacked(). Returns cf_format_packet's
 * return code; *ev_out is only set when that code is 0. */
static int format_and_unpack(const formatter_config_t *cfg, const cf_packet_item_t *pkt,
                             Cloudflow__V1__CloudFlowEvent **ev_out)
{
    cf_event_item_t item;
    int rc;

    memset(&item, 0, sizeof(item));
    rc = cf_format_packet(cfg, pkt, &item);
    if (rc != 0)
        return rc;

    *ev_out = cloudflow__v1__cloud_flow_event__unpack(NULL, item.payload_len, item.payload);
    CU_ASSERT_PTR_NOT_NULL_FATAL(*ev_out);
    return 0;
}

/* Builds a minimal Ethernet/IPv4/UDP frame around `udp_payload` into `frame`
 * (which must be at least 42 + payload_len bytes). Returns the total frame
 * length. Checksums left zero (cf_decap_udp does not verify them). */
static size_t build_udp_frame(uint8_t *frame, uint16_t src_port, uint16_t dst_port,
                              const uint8_t *udp_payload, size_t payload_len)
{
    size_t ip_total = 20 + 8 + payload_len;
    size_t udp_len = 8 + payload_len;
    size_t off = 0;

    /* Ethernet: dst mac, src mac, ethertype IPv4. */
    memset(frame + off, 0x02, 6); off += 6;   /* dst 02:02:02:02:02:02 */
    memset(frame + off, 0x03, 6); off += 6;   /* src 03:03:03:03:03:03 */
    frame[off++] = 0x08; frame[off++] = 0x00; /* 0x0800 */

    /* IPv4 header. */
    frame[off++] = 0x45;                       /* v4, IHL 5 */
    frame[off++] = 0x00;                       /* DSCP/ECN */
    frame[off++] = (uint8_t)(ip_total >> 8);
    frame[off++] = (uint8_t)(ip_total & 0xff);
    frame[off++] = 0x00; frame[off++] = 0x00;  /* id */
    frame[off++] = 0x00; frame[off++] = 0x00;  /* flags/frag */
    frame[off++] = 64;                         /* ttl */
    frame[off++] = 17;                         /* proto UDP */
    frame[off++] = 0x00; frame[off++] = 0x00;  /* checksum (unverified) */
    frame[off++] = 192; frame[off++] = 0; frame[off++] = 2; frame[off++] = 10;  /* src 192.0.2.10 */
    frame[off++] = 192; frame[off++] = 0; frame[off++] = 2; frame[off++] = 20;  /* dst 192.0.2.20 */

    /* UDP header. */
    frame[off++] = (uint8_t)(src_port >> 8); frame[off++] = (uint8_t)(src_port & 0xff);
    frame[off++] = (uint8_t)(dst_port >> 8); frame[off++] = (uint8_t)(dst_port & 0xff);
    frame[off++] = (uint8_t)(udp_len >> 8); frame[off++] = (uint8_t)(udp_len & 0xff);
    frame[off++] = 0x00; frame[off++] = 0x00;  /* checksum */

    memcpy(frame + off, udp_payload, payload_len);
    off += payload_len;

    return off;
}

static void frame_to_item(const uint8_t *frame, size_t len, cf_packet_item_t *item)
{
    memset(item, 0, sizeof(*item));
    item->observed_time_unix_nano = 1730000000123456789LL;
    item->packet_len = (uint32_t)len;
    item->captured_len = (uint32_t)len;
    memcpy(item->data, frame, len);
}

/* ---- envelope assertions shared by the fixture tests ------------------- */

static void assert_common_envelope(const Cloudflow__V1__CloudFlowEvent *ev,
                                   int64_t expected_observed_ns,
                                   const char *source_type, const char *event_type,
                                   const char *payload_schema, const char *stream_name)
{
    const Cloudflow__V1__EventEnvelope *e = ev->envelope;

    CU_ASSERT_PTR_NOT_NULL_FATAL(e);
    CU_ASSERT_EQUAL(strlen(e->event_id), 32);
    CU_ASSERT_EQUAL(e->schema_version, 1);
    CU_ASSERT_STRING_EQUAL(e->source_type, source_type);
    CU_ASSERT_STRING_EQUAL(e->source_host, "dhcp-test-01");
    CU_ASSERT_STRING_EQUAL(e->source_instance, "inst-a");
    CU_ASSERT_STRING_EQUAL(e->capture_interface, "eth0");
    CU_ASSERT_STRING_EQUAL(e->observation_method, "pcap-replay");
    CU_ASSERT_EQUAL(e->observed_time_unix_nano, expected_observed_ns);
    CU_ASSERT_TRUE(e->ingest_time_unix_nano > 0);
    CU_ASSERT_STRING_EQUAL(e->event_type, event_type);
    CU_ASSERT_EQUAL(e->visibility,
                    CLOUDFLOW__V1__VISIBILITY_LEVEL__VISIBILITY_PACKET_PAYLOAD);
    CU_ASSERT_EQUAL(e->confidence,
                    CLOUDFLOW__V1__OBSERVATION_CONFIDENCE__OBSERVATION_CONFIDENCE_OBSERVED);
    CU_ASSERT_STRING_EQUAL(e->payload_schema, payload_schema);
    CU_ASSERT_STRING_EQUAL(e->stream_name, stream_name);
}

/* ---- fixture tests ----------------------------------------------------- */

static void test_v4_discover(void)
{
    cf_source_stats_t stats;
    formatter_config_t cfg = make_cfg(&stats);
    cf_packet_item_t pkt;
    Cloudflow__V1__CloudFlowEvent *ev = NULL;

    memset(&stats, 0, sizeof(stats));
    CU_ASSERT_EQUAL_FATAL(load_fixture_frame("v4_discover", &pkt), 0);
    CU_ASSERT_EQUAL_FATAL(format_and_unpack(&cfg, &pkt, &ev), 0);

    assert_common_envelope(ev, pkt.observed_time_unix_nano, "dhcpv4", "dhcpv4.discover.observed",
                           "cloudflow.v1.DhcpV4PacketEvent", "cloudflow:v1:wire:dhcpv4");

    CU_ASSERT_EQUAL(ev->payload_case, CLOUDFLOW__V1__CLOUD_FLOW_EVENT__PAYLOAD_DHCPV4_PACKET);
    CU_ASSERT_PTR_NOT_NULL_FATAL(ev->dhcpv4_packet);
    CU_ASSERT_PTR_NOT_NULL_FATAL(ev->dhcpv4_packet->decoded);
    CU_ASSERT_STRING_EQUAL(ev->dhcpv4_packet->decoded->message_type_name, "DISCOVER");

    /* PacketObservation attached by the formatter (not the parser). */
    CU_ASSERT_PTR_NOT_NULL_FATAL(ev->dhcpv4_packet->packet);
    CU_ASSERT_PTR_NOT_NULL_FATAL(ev->dhcpv4_packet->packet->transport);
    CU_ASSERT_EQUAL(ev->dhcpv4_packet->packet->transport->dst_port, 67);
    CU_ASSERT_PTR_NOT_NULL_FATAL(ev->dhcpv4_packet->packet->network);
    CU_ASSERT_EQUAL(ev->dhcpv4_packet->packet->network->protocol,
                    CLOUDFLOW__V1__NETWORK_LAYER_OBSERVATION__NETWORK_PROTOCOL__NETWORK_PROTOCOL_IPV4);

    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.events_formatted_total), 1);
    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.events_formatted_dhcpv4_total), 1);

    cloudflow__v1__cloud_flow_event__free_unpacked(ev, NULL);
}

static void test_v4_ack(void)
{
    cf_source_stats_t stats;
    formatter_config_t cfg = make_cfg(&stats);
    cf_packet_item_t pkt;
    Cloudflow__V1__CloudFlowEvent *ev = NULL;

    memset(&stats, 0, sizeof(stats));
    CU_ASSERT_EQUAL_FATAL(load_fixture_frame("v4_ack", &pkt), 0);
    CU_ASSERT_EQUAL_FATAL(format_and_unpack(&cfg, &pkt, &ev), 0);

    assert_common_envelope(ev, pkt.observed_time_unix_nano, "dhcpv4", "dhcpv4.ack.observed",
                           "cloudflow.v1.DhcpV4PacketEvent", "cloudflow:v1:wire:dhcpv4");
    CU_ASSERT_EQUAL(ev->payload_case, CLOUDFLOW__V1__CLOUD_FLOW_EVENT__PAYLOAD_DHCPV4_PACKET);
    CU_ASSERT_STRING_EQUAL(ev->dhcpv4_packet->decoded->message_type_name, "ACK");

    cloudflow__v1__cloud_flow_event__free_unpacked(ev, NULL);
}

static void test_v4_vlan_discover(void)
{
    cf_source_stats_t stats;
    formatter_config_t cfg = make_cfg(&stats);
    cf_packet_item_t pkt;
    Cloudflow__V1__CloudFlowEvent *ev = NULL;
    const Cloudflow__V1__LinkLayerObservation *link;

    memset(&stats, 0, sizeof(stats));
    CU_ASSERT_EQUAL_FATAL(load_fixture_frame("v4_vlan_discover", &pkt), 0);
    CU_ASSERT_EQUAL_FATAL(format_and_unpack(&cfg, &pkt, &ev), 0);

    assert_common_envelope(ev, pkt.observed_time_unix_nano, "dhcpv4", "dhcpv4.discover.observed",
                           "cloudflow.v1.DhcpV4PacketEvent", "cloudflow:v1:wire:dhcpv4");

    link = ev->dhcpv4_packet->packet->link;
    CU_ASSERT_PTR_NOT_NULL_FATAL(link);
    CU_ASSERT_EQUAL_FATAL(link->n_vlan_ids, 1);
    CU_ASSERT_EQUAL(link->vlan_ids[0], 100);

    cloudflow__v1__cloud_flow_event__free_unpacked(ev, NULL);
}

static void test_v6_solicit(void)
{
    cf_source_stats_t stats;
    formatter_config_t cfg = make_cfg(&stats);
    cf_packet_item_t pkt;
    Cloudflow__V1__CloudFlowEvent *ev = NULL;

    memset(&stats, 0, sizeof(stats));
    CU_ASSERT_EQUAL_FATAL(load_fixture_frame("v6_solicit", &pkt), 0);
    CU_ASSERT_EQUAL_FATAL(format_and_unpack(&cfg, &pkt, &ev), 0);

    assert_common_envelope(ev, pkt.observed_time_unix_nano, "dhcpv6", "dhcpv6.solicit.observed",
                           "cloudflow.v1.DhcpV6PacketEvent", "cloudflow:v1:wire:dhcpv6");
    CU_ASSERT_EQUAL(ev->payload_case, CLOUDFLOW__V1__CLOUD_FLOW_EVENT__PAYLOAD_DHCPV6_PACKET);
    CU_ASSERT_PTR_NOT_NULL_FATAL(ev->dhcpv6_packet);
    CU_ASSERT_PTR_NOT_NULL_FATAL(ev->dhcpv6_packet->packet);
    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.events_formatted_dhcpv6_total), 1);

    cloudflow__v1__cloud_flow_event__free_unpacked(ev, NULL);
}

static void test_v6_reply_assigned_address(void)
{
    cf_source_stats_t stats;
    formatter_config_t cfg = make_cfg(&stats);
    cf_packet_item_t pkt;
    Cloudflow__V1__CloudFlowEvent *ev = NULL;
    const Cloudflow__V1__DhcpV6DecodedOptions *dec;
    int found = 0;
    size_t i;

    memset(&stats, 0, sizeof(stats));
    CU_ASSERT_EQUAL_FATAL(load_fixture_frame("v6_reply", &pkt), 0);
    CU_ASSERT_EQUAL_FATAL(format_and_unpack(&cfg, &pkt, &ev), 0);

    assert_common_envelope(ev, pkt.observed_time_unix_nano, "dhcpv6", "dhcpv6.reply.observed",
                           "cloudflow.v1.DhcpV6PacketEvent", "cloudflow:v1:wire:dhcpv6");

    dec = ev->dhcpv6_packet->decoded;
    CU_ASSERT_PTR_NOT_NULL_FATAL(dec);
    for (i = 0; i < dec->n_assigned_addresses; i++)
        if (strcmp(dec->assigned_addresses[i], "2001:db8::50") == 0)
            found = 1;
    CU_ASSERT_TRUE(found);

    cloudflow__v1__cloud_flow_event__free_unpacked(ev, NULL);
}

/* ---- event-id determinism ---------------------------------------------- */

static void test_event_id_deterministic(void)
{
    cf_source_stats_t stats;
    formatter_config_t cfg = make_cfg(&stats);
    cf_packet_item_t pkt;
    Cloudflow__V1__CloudFlowEvent *a = NULL;
    Cloudflow__V1__CloudFlowEvent *b = NULL;

    memset(&stats, 0, sizeof(stats));
    CU_ASSERT_EQUAL_FATAL(load_fixture_frame("v4_discover", &pkt), 0);
    CU_ASSERT_EQUAL_FATAL(format_and_unpack(&cfg, &pkt, &a), 0);
    CU_ASSERT_EQUAL_FATAL(format_and_unpack(&cfg, &pkt, &b), 0);

    /* Deterministic identity (D5): same source/interface/time/frame -> same id. */
    CU_ASSERT_STRING_EQUAL(a->envelope->event_id, b->envelope->event_id);
    CU_ASSERT_EQUAL(strlen(a->envelope->event_id), 32);

    cloudflow__v1__cloud_flow_event__free_unpacked(a, NULL);
    cloudflow__v1__cloud_flow_event__free_unpacked(b, NULL);
}

/* ---- skip / robustness ------------------------------------------------- */

static void test_non_dhcp_skip(void)
{
    cf_source_stats_t stats;
    formatter_config_t cfg = make_cfg(&stats);
    uint8_t payload[32];
    uint8_t frame[128];
    size_t flen;
    cf_packet_item_t pkt;
    cf_event_item_t item;
    int rc;

    memset(&stats, 0, sizeof(stats));
    memset(payload, 0xAB, sizeof(payload));
    flen = build_udp_frame(frame, 40000, 12345, payload, sizeof(payload));
    frame_to_item(frame, flen, &pkt);

    memset(&item, 0, sizeof(item));
    rc = cf_format_packet(&cfg, &pkt, &item);
    CU_ASSERT_EQUAL(rc, CF_FORMAT_SKIP);
    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.packets_skipped_total), 1);
    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.events_formatted_total), 0);
}

static void test_garbage_frame_no_crash(void)
{
    cf_source_stats_t stats;
    formatter_config_t cfg = make_cfg(&stats);
    cf_packet_item_t pkt;
    cf_event_item_t item;
    size_t i;
    int rc;

    memset(&stats, 0, sizeof(stats));
    memset(&pkt, 0, sizeof(pkt));
    for (i = 0; i < 200; i++)
        pkt.data[i] = (uint8_t)(i * 37 + 11);
    pkt.packet_len = 200;
    pkt.captured_len = 200;

    memset(&item, 0, sizeof(item));
    rc = cf_format_packet(&cfg, &pkt, &item);
    /* Must not crash; a random frame is either non-UDP or an undecodable
     * DHCP payload -- both are SKIP, never a hard error. */
    CU_ASSERT_EQUAL(rc, CF_FORMAT_SKIP);
}

/* ---- D11 oversize path ------------------------------------------------- */

/* Builds a DHCPv4 payload whose option 119 (domain search) is a compression
 * "bomb": M leading 2-byte pointers all referencing one shared label chain,
 * so the decoded repeated domain_search field balloons far past the packed
 * event's 8192-byte cap while the wire payload stays small (mirrors the
 * calibration probe used while implementing WP-10). Returns payload length. */
static size_t build_oversize_dhcpv4_payload(uint8_t *payload, int M)
{
    const int chain_labels = 20; /* 63-byte labels in the shared chain */
    uint8_t concat[4096];
    size_t clen = 0;
    size_t chain_start;
    size_t off = 0;
    size_t cpos;
    int i;

    /* BOOTP fixed header (236 bytes) + magic cookie. Zero op/htype is fine:
     * the parser still produces a tree; message type comes from option 53. */
    memset(payload, 0, 236);
    off = 236;
    payload[off++] = 99; payload[off++] = 130; payload[off++] = 83; payload[off++] = 99;

    /* option 53: DISCOVER */
    payload[off++] = 53; payload[off++] = 1; payload[off++] = 1;

    /* Build the concatenated option-119 value: M pointers then the chain. */
    chain_start = (size_t)M * 2;
    for (i = 0; i < M; i++) {
        concat[clen++] = (uint8_t)(0xC0 | ((chain_start >> 8) & 0x3f));
        concat[clen++] = (uint8_t)(chain_start & 0xff);
    }
    for (i = 0; i < chain_labels; i++) {
        concat[clen++] = 63;
        memset(concat + clen, 'a', 63);
        clen += 63;
    }
    concat[clen++] = 0;

    /* Fragment into option-119 instances of <=250 bytes (RFC 3396). */
    cpos = 0;
    while (cpos < clen) {
        size_t take = clen - cpos;
        if (take > 250)
            take = 250;
        payload[off++] = 119;
        payload[off++] = (uint8_t)take;
        memcpy(payload + off, concat + cpos, take);
        off += take;
        cpos += take;
    }

    payload[off++] = 255; /* end */
    return off;
}

/* D11 success branch: an event just over 8192 whose raw_dhcp_payload is a
 * big enough slice that dropping it (and setting raw_payload_truncated) brings
 * the re-pack back under the cap. M=3 lands in that window: with the ~1.5 KiB
 * wire payload the first pack exceeds 8192, without it the pack fits. */
static void test_d11_success(void)
{
    cf_source_stats_t stats;
    formatter_config_t cfg = make_cfg(&stats);
    uint8_t payload[2048];
    uint8_t frame[2048];
    size_t plen, flen;
    cf_packet_item_t pkt;
    Cloudflow__V1__CloudFlowEvent *ev = NULL;
    int rc;

    memset(&stats, 0, sizeof(stats));
    plen = build_oversize_dhcpv4_payload(payload, 3);
    flen = build_udp_frame(frame, 68, 67, payload, plen);
    CU_ASSERT_TRUE_FATAL(flen <= CLOUDFLOW_PACKET_MAX_SIZE);
    frame_to_item(frame, flen, &pkt);

    rc = format_and_unpack(&cfg, &pkt, &ev);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    CU_ASSERT_EQUAL(ev->payload_case, CLOUDFLOW__V1__CLOUD_FLOW_EVENT__PAYLOAD_DHCPV4_PACKET);
    CU_ASSERT_TRUE(ev->dhcpv4_packet->raw_payload_truncated);
    CU_ASSERT_EQUAL(ev->dhcpv4_packet->raw_dhcp_payload.len, 0);
    CU_ASSERT_TRUE(pkt.captured_len <= CLOUDFLOW_EVENT_MAX_SIZE); /* sanity */
    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.events_oversize_dropped_total), 0);
    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.events_formatted_total), 1);

    cloudflow__v1__cloud_flow_event__free_unpacked(ev, NULL);
}

/* D11 drop branch: the amplification lands in the decoded domain_search
 * (which the raw-payload drop cannot shrink), so even after dropping
 * raw_dhcp_payload the event still exceeds the cap and is dropped + counted
 * rather than emitted. M=8 is comfortably past the rescue window. */
static void test_d11_drop(void)
{
    cf_source_stats_t stats;
    formatter_config_t cfg = make_cfg(&stats);
    uint8_t payload[2048];
    uint8_t frame[2048];
    size_t plen, flen;
    cf_packet_item_t pkt;
    cf_event_item_t item;
    int rc;

    memset(&stats, 0, sizeof(stats));
    plen = build_oversize_dhcpv4_payload(payload, 8);
    flen = build_udp_frame(frame, 68, 67, payload, plen);
    CU_ASSERT_TRUE_FATAL(flen <= CLOUDFLOW_PACKET_MAX_SIZE);
    frame_to_item(frame, flen, &pkt);

    memset(&item, 0, sizeof(item));
    rc = cf_format_packet(&cfg, &pkt, &item);
    CU_ASSERT_EQUAL(rc, CF_FORMAT_SKIP);
    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.events_oversize_dropped_total), 1);
    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.events_formatted_total), 0);
}

/* ---- registration ------------------------------------------------------ */

int main(void)
{
    CU_pSuite s;

    if (CU_initialize_registry() != CUE_SUCCESS)
        return (int)CU_get_error();

    s = CU_add_suite("formatter (WP-10)", NULL, NULL);
    if (!s) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    CU_add_test(s, "v4 discover: envelope + observation + payload", test_v4_discover);
    CU_add_test(s, "v4 ack: event_type + message type", test_v4_ack);
    CU_add_test(s, "v4 vlan discover: vlan id in link observation", test_v4_vlan_discover);
    CU_add_test(s, "v6 solicit: dhcpv6 envelope + oneof", test_v6_solicit);
    CU_add_test(s, "v6 reply: assigned address decoded", test_v6_reply_assigned_address);
    CU_add_test(s, "event_id deterministic across calls", test_event_id_deterministic);
    CU_add_test(s, "non-DHCP UDP frame -> skip", test_non_dhcp_skip);
    CU_add_test(s, "garbage frame -> skip, no crash", test_garbage_frame_no_crash);
    CU_add_test(s, "D11 success -> raw payload dropped, event decodable", test_d11_success);
    CU_add_test(s, "D11 drop -> still oversize after drop, counted+skipped", test_d11_drop);

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();

    {
        unsigned int failures = CU_get_number_of_failures();
        CU_cleanup_registry();
        return failures ? 1 : 0;
    }
}
