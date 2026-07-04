/* CUnit tests for the WP-DNS07 DNS event stage (src/dns_stage.c): the
 * decap + parse + classify + correlate + sample + encode pipeline stage
 * (docs/dns-source.md, DNS-D1/D3/D4/D6/D7/D8/D9).
 *
 * The stage is driven end to end offline. The committed fixture pcaps
 * (tests/fixtures/dns/) are loaded into cf_packet_item_t via the tested
 * cf_pcap_replay path; the sampling batch is hand-built so the correlation
 * keys (and therefore the deterministic sample decisions) vary across
 * transactions. Every produced event is popped off the `out` queue and its
 * protobuf decoded so fields can be asserted. Runs clean under ASan
 * (make test-asan): the context-ownership + free-drain path across
 * observed / unanswered / unmatched / sampled-out is the key check.
 *
 * Follows the registry/main pattern of the sibling correlation/leg_classify/
 * sampling suites and the DHCP formatter_test.
 */

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "cloudflow.h"
#include "cf_queue.h"
#include "cf_stats.h"
#include "cf_pcap_replay.h"
#include "cf_rx_stats.h"

#include "cloudflow/v1/envelope.pb-c.h"

#include "dns_stage.h"

#ifndef FIXTURES_DIR
#define FIXTURES_DIR "../../tests/fixtures/dns"
#endif

/* 5-second query timeout, in nanoseconds. */
#define TIMEOUT_NS (5000LL * 1000LL * 1000LL)

static const uint8_t CLIENT_IP[4] = { 192, 0, 2, 10 };
static const uint8_t SERVER_IP[4] = { 192, 0, 2, 53 };

/* ---- config + queue helpers ------------------------------------------------ */

static dns_stage_config_t make_cfg(cf_queue_t *out, cf_dns_source_stats_t *stats,
                                   cf_dns_emit_mode_t mode, uint32_t denom)
{
    dns_stage_config_t cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.source_host = "dns-test-01";
    cfg.source_instance = "inst-a";
    cfg.capture_interface = "eth0";
    cfg.observation_method = "pcap-replay";
    cfg.out = out;
    cfg.stats = stats;
    cfg.on_full = CF_ONFULL_DROP_NEWEST;
    cfg.correlator.capacity = 1024;
    cfg.correlator.query_timeout_nanos = TIMEOUT_NS;
    cfg.correlator.on_table_full = CF_DNS_ON_FULL_DROP_NEWEST;
    cfg.local_addrs = NULL;
    cfg.backend_addrs = NULL;
    cfg.emit_policy.mode = mode;
    cfg.emit_policy.sample_denominator = denom;
    return cfg;
}

/* Loads the single frame of a fixture pcap into `out` via the tested
 * pcap_replay_file() path, overriding its capture time so RTT/timeout logic is
 * deterministic. Returns 0 on success. */
static int load_frame(const char *name, int64_t observed_ns, cf_packet_item_t *out)
{
    char path[512];
    cf_queue_t q;
    cf_rx_stats_t st;
    long n;
    int rc = -1;

    memset(&st, 0, sizeof(st));
    snprintf(path, sizeof(path), "%s/%s.pcap", FIXTURES_DIR, name);

    if (cf_queue_init(&q, 8, sizeof(cf_packet_item_t)) != 0)
        return -1;

    n = pcap_replay_file(path, &q, &st, CF_ONFULL_DROP_NEWEST);
    if (n >= 1 && cf_queue_pop(&q, out) == 0) {
        out->observed_time_unix_nano = observed_ns;
        rc = 0;
    }

    cf_queue_destroy(&q);
    return rc;
}

/* Pops one event off `out` and decodes it. Returns the decoded event (caller
 * frees with cloudflow__v1__cloud_flow_event__free_unpacked) or NULL if the
 * queue was empty. */
static Cloudflow__V1__CloudFlowEvent *pop_event(cf_queue_t *out)
{
    cf_event_item_t item;

    if (cf_queue_pop(out, &item) != 0)
        return NULL;
    return cloudflow__v1__cloud_flow_event__unpack(NULL, item.payload_len, item.payload);
}

/* ---- hand-built DNS-over-UDP frames (for the sampling batch) --------------- */

/* Appends the wire form of "www.example.com". Returns the byte count. */
static size_t put_qname(uint8_t *p)
{
    static const uint8_t n[] = { 3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p',
                                 'l', 'e', 3, 'c', 'o', 'm', 0 };
    memcpy(p, n, sizeof(n));
    return sizeof(n);
}

/* Builds a bare DNS message. When `qr` is set it is a response (rcode folded
 * in); `answer` adds a single A record whose owner is a compression pointer to
 * the question name. Returns the message length. */
static size_t build_dns_msg(uint8_t *m, uint16_t id, int qr, uint16_t qtype,
                            uint16_t rcode, int answer)
{
    size_t o = 0;
    uint16_t flags = qr ? (uint16_t)(0x8180u | (rcode & 0x0f)) : 0x0100u;
    uint16_t an = (uint16_t)((qr && answer) ? 1 : 0);

    m[o++] = (uint8_t)(id >> 8); m[o++] = (uint8_t)(id & 0xff);
    m[o++] = (uint8_t)(flags >> 8); m[o++] = (uint8_t)(flags & 0xff);
    m[o++] = 0; m[o++] = 1;                 /* qdcount */
    m[o++] = (uint8_t)(an >> 8); m[o++] = (uint8_t)(an & 0xff);
    m[o++] = 0; m[o++] = 0;                 /* nscount */
    m[o++] = 0; m[o++] = 0;                 /* arcount */

    o += put_qname(m + o);
    m[o++] = (uint8_t)(qtype >> 8); m[o++] = (uint8_t)(qtype & 0xff);
    m[o++] = 0; m[o++] = 1;                 /* class IN */

    if (an) {
        m[o++] = 0xC0; m[o++] = 0x0C;       /* name -> ptr to offset 12 */
        m[o++] = (uint8_t)(qtype >> 8); m[o++] = (uint8_t)(qtype & 0xff);
        m[o++] = 0; m[o++] = 1;             /* class IN */
        m[o++] = 0; m[o++] = 0; m[o++] = 0; m[o++] = 60; /* ttl */
        m[o++] = 0; m[o++] = 4;             /* rdlength */
        m[o++] = 192; m[o++] = 0; m[o++] = 2; m[o++] = 80; /* A 192.0.2.80 */
    }
    return o;
}

/* Wraps `payload` in an Ethernet/IPv4/UDP frame. Checksums are left zero
 * (cf_decap_udp does not verify them). Returns the frame length. */
static size_t build_udp_frame(uint8_t *frame, const uint8_t src_ip[4],
                              const uint8_t dst_ip[4], uint16_t sport, uint16_t dport,
                              const uint8_t *payload, size_t plen)
{
    size_t ip_total = 20 + 8 + plen;
    size_t udp_len = 8 + plen;
    size_t off = 0;

    memset(frame + off, 0x02, 6); off += 6;  /* dst mac */
    memset(frame + off, 0x03, 6); off += 6;  /* src mac */
    frame[off++] = 0x08; frame[off++] = 0x00; /* IPv4 */

    frame[off++] = 0x45; frame[off++] = 0x00;
    frame[off++] = (uint8_t)(ip_total >> 8); frame[off++] = (uint8_t)(ip_total & 0xff);
    frame[off++] = 0x00; frame[off++] = 0x00;
    frame[off++] = 0x00; frame[off++] = 0x00;
    frame[off++] = 64; frame[off++] = 17;     /* ttl, UDP */
    frame[off++] = 0x00; frame[off++] = 0x00; /* hdr checksum */
    memcpy(frame + off, src_ip, 4); off += 4;
    memcpy(frame + off, dst_ip, 4); off += 4;

    frame[off++] = (uint8_t)(sport >> 8); frame[off++] = (uint8_t)(sport & 0xff);
    frame[off++] = (uint8_t)(dport >> 8); frame[off++] = (uint8_t)(dport & 0xff);
    frame[off++] = (uint8_t)(udp_len >> 8); frame[off++] = (uint8_t)(udp_len & 0xff);
    frame[off++] = 0x00; frame[off++] = 0x00;

    memcpy(frame + off, payload, plen); off += plen;
    return off;
}

/* Builds a query or response packet item for the given transaction shape. */
static void make_dns_pkt(cf_packet_item_t *pkt, uint16_t id, int qr, uint16_t client_port,
                         uint16_t qtype, uint16_t rcode, int answer, int64_t observed_ns)
{
    uint8_t msg[64];
    size_t mlen = build_dns_msg(msg, id, qr, qtype, rcode, answer);
    size_t flen;

    memset(pkt, 0, sizeof(*pkt));
    if (qr) /* response: server:53 -> client:client_port */
        flen = build_udp_frame(pkt->data, SERVER_IP, CLIENT_IP, 53, client_port, msg, mlen);
    else    /* query: client:client_port -> server:53 */
        flen = build_udp_frame(pkt->data, CLIENT_IP, SERVER_IP, client_port, 53, msg, mlen);

    pkt->captured_len = (uint32_t)flen;
    pkt->packet_len = (uint32_t)flen;
    pkt->observed_time_unix_nano = observed_ns;
}

/* ---- tests ----------------------------------------------------------------- */

static void test_observed_pair(void)
{
    cf_queue_t out;
    cf_dns_source_stats_t stats;
    dns_stage_config_t cfg;
    dns_stage_t *stage;
    cf_packet_item_t q, r;
    Cloudflow__V1__CloudFlowEvent *ev;
    Cloudflow__V1__DnsTransactionEvent *txn;

    memset(&stats, 0, sizeof(stats));
    CU_ASSERT_EQUAL_FATAL(cf_queue_init(&out, 64, sizeof(cf_event_item_t)), 0);
    cfg = make_cfg(&out, &stats, CF_DNS_EMIT_ALL, 0);
    stage = dns_stage_new(&cfg);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stage);

    CU_ASSERT_EQUAL_FATAL(load_frame("q_a_query", 1000000, &q), 0);
    CU_ASSERT_EQUAL_FATAL(load_frame("q_a_response", 1500000, &r), 0);

    CU_ASSERT_EQUAL(dns_stage_process_packet(stage, &q), 0);
    CU_ASSERT_EQUAL(dns_stage_process_packet(stage, &r), 0);

    ev = pop_event(&out);
    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);
    /* exactly one event */
    CU_ASSERT_EQUAL(cf_queue_length(&out), 0);

    CU_ASSERT_PTR_NOT_NULL_FATAL(ev->envelope);
    CU_ASSERT_STRING_EQUAL(ev->envelope->event_type, "dns.transaction.observed");
    CU_ASSERT_STRING_EQUAL(ev->envelope->source_type, "dns");
    CU_ASSERT_STRING_EQUAL(ev->envelope->payload_schema, "cloudflow.v1.DnsTransactionEvent");
    CU_ASSERT_STRING_EQUAL(ev->envelope->stream_name, cf_stream_name(CF_STREAM_DNS));
    CU_ASSERT_EQUAL(ev->envelope->observed_time_unix_nano, 1000000); /* query time */
    CU_ASSERT_EQUAL(strlen(ev->envelope->event_id), 32);

    CU_ASSERT_EQUAL_FATAL(ev->payload_case, CLOUDFLOW__V1__CLOUD_FLOW_EVENT__PAYLOAD_DNS_TRANSACTION);
    txn = ev->dns_transaction;
    CU_ASSERT_PTR_NOT_NULL_FATAL(txn);
    CU_ASSERT_TRUE(txn->rtt_valid);
    CU_ASSERT_EQUAL(txn->rtt_nanos, 500000);
    CU_ASSERT_TRUE(txn->rtt_nanos >= 0);
    CU_ASSERT_EQUAL(txn->role, CLOUDFLOW__V1__DNS_LEG__DNS_LEG_RECURSION_UPSTREAM);
    CU_ASSERT_STRING_EQUAL(txn->client_ip, "192.0.2.10");
    CU_ASSERT_STRING_EQUAL(txn->server_ip, "192.0.2.53");
    CU_ASSERT_EQUAL(txn->client_port, 40000);

    /* decoded question + answer both present */
    CU_ASSERT_PTR_NOT_NULL_FATAL(txn->query);
    CU_ASSERT_PTR_NOT_NULL_FATAL(txn->response);
    CU_ASSERT_TRUE(txn->query->n_questions >= 1);
    CU_ASSERT_STRING_EQUAL(txn->query->questions[0]->qname, "www.example.com");
    CU_ASSERT_TRUE(txn->response->n_answers >= 1);
    CU_ASSERT_PTR_NOT_NULL(txn->query_packet);
    CU_ASSERT_PTR_NOT_NULL(txn->response_packet);

    cloudflow__v1__cloud_flow_event__free_unpacked(ev, NULL);

    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.dns_queries_parsed_total), 1);
    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.dns_responses_parsed_total), 1);
    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.dns_transactions_emitted_total), 1);
    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.dns_transactions_emitted_recursion_upstream_total), 1);

    dns_stage_free(stage);
    CU_ASSERT_EQUAL(cf_queue_length(&out), 0); /* nothing pending -> no drain events */
    cf_queue_destroy(&out);
}

/* WP-DNS11a: the emitted DnsTransactionEvent carries the operator service_role
 * for its server-side IP (192.0.2.53 in the fixtures), empty when unmapped or
 * when there is no role map. Drives the same observed query+response pair. */
static Cloudflow__V1__DnsTransactionEvent *run_observed_with_role_map(
    const cf_dns_role_map_t *role_map, Cloudflow__V1__CloudFlowEvent **ev_out,
    cf_queue_t *out, cf_dns_source_stats_t *stats, dns_stage_t **stage_out)
{
    dns_stage_config_t cfg;
    dns_stage_t *stage;
    cf_packet_item_t q, r;
    Cloudflow__V1__CloudFlowEvent *ev;

    cfg = make_cfg(out, stats, CF_DNS_EMIT_ALL, 0);
    cfg.role_map = role_map;
    stage = dns_stage_new(&cfg);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stage);

    CU_ASSERT_EQUAL_FATAL(load_frame("q_a_query", 1000000, &q), 0);
    CU_ASSERT_EQUAL_FATAL(load_frame("q_a_response", 1500000, &r), 0);
    CU_ASSERT_EQUAL(dns_stage_process_packet(stage, &q), 0);
    CU_ASSERT_EQUAL(dns_stage_process_packet(stage, &r), 0);

    ev = pop_event(out);
    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);
    *ev_out = ev;
    *stage_out = stage;
    return ev->dns_transaction;
}

static void test_service_role_tagging(void)
{
    cf_queue_t out;
    cf_dns_source_stats_t stats;
    cf_dns_role_map_t *map;
    Cloudflow__V1__CloudFlowEvent *ev;
    Cloudflow__V1__DnsTransactionEvent *txn;
    dns_stage_t *stage;

    /* (1) server 192.0.2.53 mapped to "recursor" -> the decoded event carries it. */
    memset(&stats, 0, sizeof(stats));
    CU_ASSERT_EQUAL_FATAL(cf_queue_init(&out, 64, sizeof(cf_event_item_t)), 0);
    map = cf_dns_role_map_new();
    CU_ASSERT_PTR_NOT_NULL_FATAL(map);
    CU_ASSERT_EQUAL(cf_dns_role_map_add_str(map, "192.0.2.53", "recursor"), 1);

    txn = run_observed_with_role_map(map, &ev, &out, &stats, &stage);
    CU_ASSERT_PTR_NOT_NULL_FATAL(txn);
    CU_ASSERT_STRING_EQUAL(txn->server_ip, "192.0.2.53");
    CU_ASSERT_PTR_NOT_NULL_FATAL(txn->service_role);
    CU_ASSERT_STRING_EQUAL(txn->service_role, "recursor");
    cloudflow__v1__cloud_flow_event__free_unpacked(ev, NULL);
    dns_stage_free(stage);
    cf_dns_role_map_free(map);
    cf_queue_destroy(&out);

    /* (2) a map that does NOT contain the server IP -> empty service_role. */
    memset(&stats, 0, sizeof(stats));
    CU_ASSERT_EQUAL_FATAL(cf_queue_init(&out, 64, sizeof(cf_event_item_t)), 0);
    map = cf_dns_role_map_new();
    CU_ASSERT_PTR_NOT_NULL_FATAL(map);
    CU_ASSERT_EQUAL(cf_dns_role_map_add_str(map, "203.0.113.9", "authoritative"), 1);

    txn = run_observed_with_role_map(map, &ev, &out, &stats, &stage);
    CU_ASSERT_PTR_NOT_NULL_FATAL(txn);
    CU_ASSERT_PTR_NOT_NULL_FATAL(txn->service_role);
    CU_ASSERT_STRING_EQUAL(txn->service_role, "");
    cloudflow__v1__cloud_flow_event__free_unpacked(ev, NULL);
    dns_stage_free(stage);
    cf_dns_role_map_free(map);
    cf_queue_destroy(&out);

    /* (3) no role map at all (NULL) -> empty service_role. */
    memset(&stats, 0, sizeof(stats));
    CU_ASSERT_EQUAL_FATAL(cf_queue_init(&out, 64, sizeof(cf_event_item_t)), 0);
    txn = run_observed_with_role_map(NULL, &ev, &out, &stats, &stage);
    CU_ASSERT_PTR_NOT_NULL_FATAL(txn);
    CU_ASSERT_PTR_NOT_NULL_FATAL(txn->service_role);
    CU_ASSERT_STRING_EQUAL(txn->service_role, "");
    cloudflow__v1__cloud_flow_event__free_unpacked(ev, NULL);
    dns_stage_free(stage);
    cf_queue_destroy(&out);
}

static void test_unanswered_on_tick(void)
{
    cf_queue_t out;
    cf_dns_source_stats_t stats;
    dns_stage_config_t cfg;
    dns_stage_t *stage;
    cf_packet_item_t q;
    Cloudflow__V1__CloudFlowEvent *ev;

    memset(&stats, 0, sizeof(stats));
    CU_ASSERT_EQUAL_FATAL(cf_queue_init(&out, 64, sizeof(cf_event_item_t)), 0);
    cfg = make_cfg(&out, &stats, CF_DNS_EMIT_ALL, 0);
    stage = dns_stage_new(&cfg);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stage);

    CU_ASSERT_EQUAL_FATAL(load_frame("q_a_query", 1000000, &q), 0);
    CU_ASSERT_EQUAL(dns_stage_process_packet(stage, &q), 0);

    /* No response ever arrives; a tick well past the timeout evicts it. */
    CU_ASSERT_EQUAL(cf_queue_length(&out), 0);
    dns_stage_tick(stage, 1000000 + TIMEOUT_NS + 1);

    ev = pop_event(&out);
    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);
    CU_ASSERT_EQUAL(cf_queue_length(&out), 0);
    CU_ASSERT_STRING_EQUAL(ev->envelope->event_type, "dns.query.unanswered");
    CU_ASSERT_PTR_NOT_NULL_FATAL(ev->dns_transaction);
    CU_ASSERT_PTR_NOT_NULL(ev->dns_transaction->query);
    CU_ASSERT_PTR_NULL(ev->dns_transaction->response);
    CU_ASSERT_FALSE(ev->dns_transaction->rtt_valid);
    cloudflow__v1__cloud_flow_event__free_unpacked(ev, NULL);

    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.dns_queries_parsed_total), 1);
    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.dns_query_unanswered_total), 1);
    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.dns_transactions_emitted_total), 1);

    dns_stage_free(stage);
    cf_queue_destroy(&out);
}

static void test_unanswered_on_free_drain(void)
{
    /* A query left pending at teardown is drained as unanswered through the
     * same emit path (the ASan free-drain check). */
    cf_queue_t out;
    cf_dns_source_stats_t stats;
    dns_stage_config_t cfg;
    dns_stage_t *stage;
    cf_packet_item_t q;
    Cloudflow__V1__CloudFlowEvent *ev;

    memset(&stats, 0, sizeof(stats));
    CU_ASSERT_EQUAL_FATAL(cf_queue_init(&out, 64, sizeof(cf_event_item_t)), 0);
    cfg = make_cfg(&out, &stats, CF_DNS_EMIT_ALL, 0);
    stage = dns_stage_new(&cfg);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stage);

    CU_ASSERT_EQUAL_FATAL(load_frame("q_aaaa_query", 2000000, &q), 0);
    CU_ASSERT_EQUAL(dns_stage_process_packet(stage, &q), 0);
    CU_ASSERT_EQUAL(cf_queue_length(&out), 0);

    dns_stage_free(stage); /* drains the pending query */

    ev = pop_event(&out);
    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);
    CU_ASSERT_STRING_EQUAL(ev->envelope->event_type, "dns.query.unanswered");
    cloudflow__v1__cloud_flow_event__free_unpacked(ev, NULL);

    cf_queue_destroy(&out);
}

static void test_unmatched_response(void)
{
    cf_queue_t out;
    cf_dns_source_stats_t stats;
    dns_stage_config_t cfg;
    dns_stage_t *stage;
    cf_packet_item_t r;
    Cloudflow__V1__CloudFlowEvent *ev;

    memset(&stats, 0, sizeof(stats));
    CU_ASSERT_EQUAL_FATAL(cf_queue_init(&out, 64, sizeof(cf_event_item_t)), 0);
    cfg = make_cfg(&out, &stats, CF_DNS_EMIT_ALL, 0);
    stage = dns_stage_new(&cfg);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stage);

    /* A response with no pending query emits immediately. */
    CU_ASSERT_EQUAL_FATAL(load_frame("q_a_response", 3000000, &r), 0);
    CU_ASSERT_EQUAL(dns_stage_process_packet(stage, &r), 0);

    ev = pop_event(&out);
    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);
    CU_ASSERT_EQUAL(cf_queue_length(&out), 0);
    CU_ASSERT_STRING_EQUAL(ev->envelope->event_type, "dns.response.unmatched");
    CU_ASSERT_PTR_NOT_NULL_FATAL(ev->dns_transaction);
    CU_ASSERT_PTR_NULL(ev->dns_transaction->query);
    CU_ASSERT_PTR_NOT_NULL(ev->dns_transaction->response);
    cloudflow__v1__cloud_flow_event__free_unpacked(ev, NULL);

    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.dns_responses_parsed_total), 1);
    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.dns_response_unmatched_total), 1);

    dns_stage_free(stage);
    cf_queue_destroy(&out);
}

static void test_tcp_pair_prefix_stripped(void)
{
    cf_queue_t out;
    cf_dns_source_stats_t stats;
    dns_stage_config_t cfg;
    dns_stage_t *stage;
    cf_packet_item_t q, r;
    Cloudflow__V1__CloudFlowEvent *ev;
    Cloudflow__V1__DnsTransactionEvent *txn;

    memset(&stats, 0, sizeof(stats));
    CU_ASSERT_EQUAL_FATAL(cf_queue_init(&out, 64, sizeof(cf_event_item_t)), 0);
    cfg = make_cfg(&out, &stats, CF_DNS_EMIT_ALL, 0);
    stage = dns_stage_new(&cfg);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stage);

    CU_ASSERT_EQUAL_FATAL(load_frame("tcp_a_query", 4000000, &q), 0);
    CU_ASSERT_EQUAL_FATAL(load_frame("tcp_a_response", 4200000, &r), 0);
    CU_ASSERT_EQUAL(dns_stage_process_packet(stage, &q), 0);
    CU_ASSERT_EQUAL(dns_stage_process_packet(stage, &r), 0);

    ev = pop_event(&out);
    CU_ASSERT_PTR_NOT_NULL_FATAL(ev);
    CU_ASSERT_EQUAL(cf_queue_length(&out), 0);
    CU_ASSERT_STRING_EQUAL(ev->envelope->event_type, "dns.transaction.observed");
    txn = ev->dns_transaction;
    CU_ASSERT_PTR_NOT_NULL_FATAL(txn);
    /* Prefix stripped correctly => the bare message parses to a real question. */
    CU_ASSERT_PTR_NOT_NULL_FATAL(txn->query);
    CU_ASSERT_TRUE(txn->query->n_questions >= 1);
    CU_ASSERT_STRING_EQUAL(txn->query->questions[0]->qname, "www.example.com");
    CU_ASSERT_TRUE(txn->rtt_valid);
    CU_ASSERT_EQUAL(txn->rtt_nanos, 200000);
    cloudflow__v1__cloud_flow_event__free_unpacked(ev, NULL);

    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.dns_tcp_partial_total), 0);
    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.dns_transactions_emitted_total), 1);

    dns_stage_free(stage);
    cf_queue_destroy(&out);
}

static void test_sampling_routine_vs_anomaly(void)
{
    cf_queue_t out;
    cf_dns_source_stats_t stats;
    dns_stage_config_t cfg;
    dns_stage_t *stage;
    cf_packet_item_t q, r;
    Cloudflow__V1__CloudFlowEvent *ev;
    const uint16_t N = 80;
    uint16_t i;
    unsigned long emitted, sampled_out;
    int64_t t = 10000000;

    memset(&stats, 0, sizeof(stats));
    CU_ASSERT_EQUAL_FATAL(cf_queue_init(&out, 256, sizeof(cf_event_item_t)), 0);
    /* PREDICATE, keep ~1 in 4 routine A NOERROR observed transactions. */
    cfg = make_cfg(&out, &stats, CF_DNS_EMIT_PREDICATE, 4);
    stage = dns_stage_new(&cfg);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stage);

    /* Distinct keys (varying dns_id + client_port) so sampling is not
     * all-or-nothing: routine A/NOERROR observed transactions. */
    for (i = 0; i < N; i++) {
        make_dns_pkt(&q, i, 0, (uint16_t)(40000 + i), 1 /*A*/, 0, 0, t);
        make_dns_pkt(&r, i, 1, (uint16_t)(40000 + i), 1 /*A*/, 0 /*NOERROR*/, 1, t + 1000);
        t += 10000;
        CU_ASSERT_EQUAL(dns_stage_process_packet(stage, &q), 0);
        CU_ASSERT_EQUAL(dns_stage_process_packet(stage, &r), 0);
    }

    emitted = (unsigned long)cf_queue_length(&out);
    sampled_out = CF_ATOMIC_READ(stats.dns_sampled_out_total);

    /* Fewer emitted than fed, and the sampled-out counter accounts for the
     * whole difference (visible loss, DNS-D8). */
    CU_ASSERT_TRUE(emitted > 0);
    CU_ASSERT_TRUE(emitted < N);
    CU_ASSERT_EQUAL(emitted + sampled_out, N);
    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.dns_transactions_emitted_total), emitted);

    /* Drain the sampled events. */
    while ((ev = pop_event(&out)) != NULL)
        cloudflow__v1__cloud_flow_event__free_unpacked(ev, NULL);

    /* Anomalies are ALWAYS emitted regardless of the aggressive denom:
     * a non-routine qtype (MX) and a non-NOERROR rcode (NXDOMAIN). */
    make_dns_pkt(&q, 5000, 0, 41000, 15 /*MX*/, 0, 0, t);
    make_dns_pkt(&r, 5000, 1, 41000, 15 /*MX*/, 0, 0, t + 1000);
    t += 10000;
    dns_stage_process_packet(stage, &q);
    dns_stage_process_packet(stage, &r);

    make_dns_pkt(&q, 5001, 0, 41001, 1 /*A*/, 0, 0, t);
    make_dns_pkt(&r, 5001, 1, 41001, 1 /*A*/, 3 /*NXDOMAIN*/, 0, t + 1000);
    t += 10000;
    dns_stage_process_packet(stage, &q);
    dns_stage_process_packet(stage, &r);

    CU_ASSERT_EQUAL(cf_queue_length(&out), 2); /* both anomalies emitted */
    while ((ev = pop_event(&out)) != NULL)
        cloudflow__v1__cloud_flow_event__free_unpacked(ev, NULL);

    dns_stage_free(stage);
    cf_queue_destroy(&out);
}

static void test_non_dns_frame_skipped(void)
{
    /* A frame that decaps but is neither udp/53 nor tcp/53 DNS still runs
     * through decap+parse; a non-DNS UDP payload that fails to parse is a
     * counted, non-fatal skip and emits nothing. */
    cf_queue_t out;
    cf_dns_source_stats_t stats;
    dns_stage_config_t cfg;
    dns_stage_t *stage;
    cf_packet_item_t pkt;
    uint8_t junk[4] = { 0xde, 0xad, 0xbe, 0xef };

    memset(&stats, 0, sizeof(stats));
    CU_ASSERT_EQUAL_FATAL(cf_queue_init(&out, 8, sizeof(cf_event_item_t)), 0);
    cfg = make_cfg(&out, &stats, CF_DNS_EMIT_ALL, 0);
    stage = dns_stage_new(&cfg);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stage);

    memset(&pkt, 0, sizeof(pkt));
    pkt.captured_len = (uint32_t)build_udp_frame(pkt.data, CLIENT_IP, SERVER_IP,
                                                 40000, 53, junk, sizeof(junk));
    pkt.packet_len = pkt.captured_len;
    pkt.observed_time_unix_nano = 7000000;

    /* < 12 bytes => cf_dns_parse fails => decode-parse-failure, skipped. */
    CU_ASSERT_EQUAL(dns_stage_process_packet(stage, &pkt), 1);
    CU_ASSERT_EQUAL(cf_queue_length(&out), 0);
    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.decode_parse_failure_total), 1);

    dns_stage_free(stage);
    cf_queue_destroy(&out);
}

/* Feeds `n` distinct lone responses (each with no pending query -> unmatched)
 * through the stage, draining and freeing the events they emit. */
static void feed_unmatched(dns_stage_t *stage, cf_queue_t *out, uint16_t base_id,
                           uint16_t n, int64_t t)
{
    cf_packet_item_t r;
    Cloudflow__V1__CloudFlowEvent *ev;
    uint16_t i;

    for (i = 0; i < n; i++) {
        make_dns_pkt(&r, (uint16_t)(base_id + i), 1, (uint16_t)(50000 + i),
                     1 /*A*/, 0, 0, t + (int64_t)i * 1000);
        CU_ASSERT_EQUAL(dns_stage_process_packet(stage, &r), 0);
    }
    while ((ev = pop_event(out)) != NULL)
        cloudflow__v1__cloud_flow_event__free_unpacked(ev, NULL);
}

/* Feeds `n` distinct lone queries, then ticks past the timeout so every one is
 * evicted as unanswered; drains and frees the emitted events. */
static void feed_unanswered(dns_stage_t *stage, cf_queue_t *out, uint16_t base_id,
                            uint16_t n, int64_t t)
{
    cf_packet_item_t q;
    Cloudflow__V1__CloudFlowEvent *ev;
    uint16_t i;

    for (i = 0; i < n; i++) {
        make_dns_pkt(&q, (uint16_t)(base_id + i), 0, (uint16_t)(41000 + i),
                     1 /*A*/, 0, 0, t + (int64_t)i * 1000);
        CU_ASSERT_EQUAL(dns_stage_process_packet(stage, &q), 0);
    }
    dns_stage_tick(stage, t + (int64_t)n * 1000 + TIMEOUT_NS + 1);
    while ((ev = pop_event(out)) != NULL)
        cloudflow__v1__cloud_flow_event__free_unpacked(ev, NULL);
}

/* Loss counters (dns_query_unanswered_total, dns_response_unmatched_total, ...)
 * must honor stats.reset_on_report exactly like every other counter: read with
 * CF_ATOMIC_READ_AND_ZERO (the reset path), each report yields ONLY the delta
 * since the last report -- NOT the correlator's running cumulative. The stage
 * ADDs per-sync deltas so this holds; the earlier STORE-of-cumulative bug made
 * the second interval re-report all prior counts. */
static void test_reset_on_report_loss_counters_per_interval(void)
{
    cf_queue_t out;
    cf_dns_source_stats_t stats;
    dns_stage_config_t cfg;
    dns_stage_t *stage;

    memset(&stats, 0, sizeof(stats));
    CU_ASSERT_EQUAL_FATAL(cf_queue_init(&out, 64, sizeof(cf_event_item_t)), 0);
    cfg = make_cfg(&out, &stats, CF_DNS_EMIT_ALL, 0);
    stage = dns_stage_new(&cfg);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stage);

    /* Interval 1: 2 unmatched + 1 unanswered. */
    feed_unmatched(stage, &out, 200, 2, 1000000);
    feed_unanswered(stage, &out, 300, 1, 2000000);

    CU_ASSERT_EQUAL(CF_ATOMIC_READ_AND_ZERO(stats.dns_response_unmatched_total), 2);
    CU_ASSERT_EQUAL(CF_ATOMIC_READ_AND_ZERO(stats.dns_query_unanswered_total), 1);

    /* Interval 2: 1 unmatched + 2 unanswered. A correct per-interval report
     * sees ONLY these; the cumulative totals are now 3 and 3 respectively. */
    feed_unmatched(stage, &out, 400, 1, 3000000);
    feed_unanswered(stage, &out, 500, 2, 4000000);

    CU_ASSERT_EQUAL(CF_ATOMIC_READ_AND_ZERO(stats.dns_response_unmatched_total), 1);
    CU_ASSERT_EQUAL(CF_ATOMIC_READ_AND_ZERO(stats.dns_query_unanswered_total), 2);

    dns_stage_free(stage);
    /* Draining pending at teardown: none left (all queries already evicted). */
    cf_queue_destroy(&out);
}

/* Without reset_on_report the same counters are read with plain CF_ATOMIC_READ
 * and accumulate across intervals -- the delta-ADD scheme keeps that correct. */
static void test_no_reset_loss_counters_cumulative(void)
{
    cf_queue_t out;
    cf_dns_source_stats_t stats;
    dns_stage_config_t cfg;
    dns_stage_t *stage;

    memset(&stats, 0, sizeof(stats));
    CU_ASSERT_EQUAL_FATAL(cf_queue_init(&out, 64, sizeof(cf_event_item_t)), 0);
    cfg = make_cfg(&out, &stats, CF_DNS_EMIT_ALL, 0);
    stage = dns_stage_new(&cfg);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stage);

    feed_unmatched(stage, &out, 600, 2, 1000000);
    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.dns_response_unmatched_total), 2); /* cumulative */

    feed_unmatched(stage, &out, 700, 3, 2000000);
    CU_ASSERT_EQUAL(CF_ATOMIC_READ(stats.dns_response_unmatched_total), 5); /* 2 + 3 */

    dns_stage_free(stage);
    cf_queue_destroy(&out);
}

/* ---- driver ---------------------------------------------------------------- */

int main(void)
{
    CU_pSuite suite;
    unsigned int failed;

    if (CU_initialize_registry() != CUE_SUCCESS)
        return (int)CU_get_error();

    suite = CU_add_suite("dns_stage", NULL, NULL);
    if (!suite) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    if (!CU_add_test(suite, "udp query+response -> one observed transaction", test_observed_pair) ||
        !CU_add_test(suite, "service_role tagged from role map (mapped/unmapped/none)", test_service_role_tagging) ||
        !CU_add_test(suite, "lone query + tick -> unanswered", test_unanswered_on_tick) ||
        !CU_add_test(suite, "pending query at teardown -> unanswered (free drain)", test_unanswered_on_free_drain) ||
        !CU_add_test(suite, "lone response -> unmatched", test_unmatched_response) ||
        !CU_add_test(suite, "tcp query+response -> observed (prefix stripped)", test_tcp_pair_prefix_stripped) ||
        !CU_add_test(suite, "sampling drops routine, always emits anomalies", test_sampling_routine_vs_anomaly) ||
        !CU_add_test(suite, "non-DNS/unparseable frame skipped", test_non_dns_frame_skipped) ||
        !CU_add_test(suite, "loss counters honor reset_on_report (per-interval deltas)",
                     test_reset_on_report_loss_counters_per_interval) ||
        !CU_add_test(suite, "loss counters cumulative without reset_on_report",
                     test_no_reset_loss_counters_cumulative)) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();

    failed = CU_get_number_of_tests_failed();
    CU_cleanup_registry();
    return failed > 0 ? 1 : 0;
}
