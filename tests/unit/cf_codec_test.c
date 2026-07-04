/* WP-02 round-trip acceptance test for libcloudflow-codec.
 *
 * Builds a Cloudflow__V1__CloudFlowEvent (with an EventEnvelope, and in
 * later suites a DhcpV4PacketEvent or DnsTransactionEvent oneof payload --
 * the latter added in WP-DNS01), packs it to wire bytes with protobuf-c,
 * unpacks it back, and asserts the fields/oneof case survive the round
 * trip. Standalone CUnit binary (build/cf_codec_test), kept separate from
 * cf_core_test so the WP-03 SOURCES list in this directory's Makefile does
 * not need to change.
 */

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cloudflow/v1/envelope.pb-c.h"

static void test_envelope_roundtrip(void)
{
    Cloudflow__V1__CloudFlowEvent event = CLOUDFLOW__V1__CLOUD_FLOW_EVENT__INIT;
    Cloudflow__V1__EventEnvelope envelope = CLOUDFLOW__V1__EVENT_ENVELOPE__INIT;
    uint8_t *buf;
    size_t packed_len;
    Cloudflow__V1__CloudFlowEvent *unpacked;

    envelope.event_id = (char *)"0123456789abcdef0123456789abcdef";
    envelope.schema_version = 1;
    envelope.source_type = (char *)"dhcpv4";
    envelope.event_type = (char *)"dhcpv4.packet.observed";

    event.envelope = &envelope;

    packed_len = cloudflow__v1__cloud_flow_event__get_packed_size(&event);
    CU_ASSERT_TRUE(packed_len > 0);

    buf = malloc(packed_len);
    CU_ASSERT_PTR_NOT_NULL_FATAL(buf);

    CU_ASSERT_EQUAL(cloudflow__v1__cloud_flow_event__pack(&event, buf), packed_len);

    unpacked = cloudflow__v1__cloud_flow_event__unpack(NULL, packed_len, buf);
    CU_ASSERT_PTR_NOT_NULL_FATAL(unpacked);

    CU_ASSERT_PTR_NOT_NULL_FATAL(unpacked->envelope);
    CU_ASSERT_STRING_EQUAL(unpacked->envelope->event_id, envelope.event_id);
    CU_ASSERT_EQUAL(unpacked->envelope->schema_version, envelope.schema_version);
    CU_ASSERT_STRING_EQUAL(unpacked->envelope->source_type, envelope.source_type);
    CU_ASSERT_STRING_EQUAL(unpacked->envelope->event_type, envelope.event_type);

    CU_ASSERT_EQUAL(unpacked->payload_case, CLOUDFLOW__V1__CLOUD_FLOW_EVENT__PAYLOAD__NOT_SET);

    cloudflow__v1__cloud_flow_event__free_unpacked(unpacked, NULL);
    free(buf);
}

static void test_dhcpv4_payload_oneof_roundtrip(void)
{
    Cloudflow__V1__CloudFlowEvent event = CLOUDFLOW__V1__CLOUD_FLOW_EVENT__INIT;
    Cloudflow__V1__EventEnvelope envelope = CLOUDFLOW__V1__EVENT_ENVELOPE__INIT;
    Cloudflow__V1__DhcpV4PacketEvent dhcpv4 = CLOUDFLOW__V1__DHCP_V4_PACKET_EVENT__INIT;
    Cloudflow__V1__DhcpV4Header header = CLOUDFLOW__V1__DHCP_V4_HEADER__INIT;
    uint8_t *buf;
    size_t packed_len;
    Cloudflow__V1__CloudFlowEvent *unpacked;

    envelope.event_id = (char *)"fedcba9876543210fedcba9876543210";
    envelope.schema_version = 1;
    envelope.source_type = (char *)"dhcpv4";
    envelope.event_type = (char *)"dhcpv4.discover.observed";

    header.op = 1;
    header.xid = 0xdeadbeef;
    header.ciaddr = (char *)"0.0.0.0";
    header.yiaddr = (char *)"0.0.0.0";

    dhcpv4.header = &header;

    event.envelope = &envelope;
    event.payload_case = CLOUDFLOW__V1__CLOUD_FLOW_EVENT__PAYLOAD_DHCPV4_PACKET;
    event.dhcpv4_packet = &dhcpv4;

    packed_len = cloudflow__v1__cloud_flow_event__get_packed_size(&event);
    CU_ASSERT_TRUE(packed_len > 0);

    buf = malloc(packed_len);
    CU_ASSERT_PTR_NOT_NULL_FATAL(buf);

    CU_ASSERT_EQUAL(cloudflow__v1__cloud_flow_event__pack(&event, buf), packed_len);

    unpacked = cloudflow__v1__cloud_flow_event__unpack(NULL, packed_len, buf);
    CU_ASSERT_PTR_NOT_NULL_FATAL(unpacked);

    CU_ASSERT_PTR_NOT_NULL_FATAL(unpacked->envelope);
    CU_ASSERT_STRING_EQUAL(unpacked->envelope->event_id, envelope.event_id);

    CU_ASSERT_EQUAL(unpacked->payload_case, CLOUDFLOW__V1__CLOUD_FLOW_EVENT__PAYLOAD_DHCPV4_PACKET);
    CU_ASSERT_PTR_NOT_NULL_FATAL(unpacked->dhcpv4_packet);
    CU_ASSERT_PTR_NOT_NULL_FATAL(unpacked->dhcpv4_packet->header);
    CU_ASSERT_EQUAL(unpacked->dhcpv4_packet->header->op, header.op);
    CU_ASSERT_EQUAL(unpacked->dhcpv4_packet->header->xid, header.xid);
    CU_ASSERT_STRING_EQUAL(unpacked->dhcpv4_packet->header->ciaddr, header.ciaddr);

    /* Oneof discipline: dhcpv4_packet/dhcpv6_packet/dhcpv4_lease share
     * storage (a C union), so payload_case -- not pointer nullness -- is
     * the authoritative discriminant that the DHCPv4 alternative was
     * selected and the others were not. */
    CU_ASSERT_EQUAL(unpacked->payload_case, CLOUDFLOW__V1__CLOUD_FLOW_EVENT__PAYLOAD_DHCPV4_PACKET);
    CU_ASSERT_NOT_EQUAL(unpacked->payload_case, CLOUDFLOW__V1__CLOUD_FLOW_EVENT__PAYLOAD_DHCPV6_PACKET);
    CU_ASSERT_NOT_EQUAL(unpacked->payload_case, CLOUDFLOW__V1__CLOUD_FLOW_EVENT__PAYLOAD_DHCPV4_LEASE);

    cloudflow__v1__cloud_flow_event__free_unpacked(unpacked, NULL);
    free(buf);
}

static void test_dns_transaction_payload_oneof_roundtrip(void)
{
    Cloudflow__V1__CloudFlowEvent event = CLOUDFLOW__V1__CLOUD_FLOW_EVENT__INIT;
    Cloudflow__V1__EventEnvelope envelope = CLOUDFLOW__V1__EVENT_ENVELOPE__INIT;
    Cloudflow__V1__DnsTransactionEvent dns_transaction = CLOUDFLOW__V1__DNS_TRANSACTION_EVENT__INIT;
    Cloudflow__V1__DnsMessage query = CLOUDFLOW__V1__DNS_MESSAGE__INIT;
    Cloudflow__V1__DnsHeader query_header = CLOUDFLOW__V1__DNS_HEADER__INIT;
    uint8_t *buf;
    size_t packed_len;
    Cloudflow__V1__CloudFlowEvent *unpacked;

    envelope.event_id = (char *)"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";
    envelope.schema_version = 1;
    envelope.source_type = (char *)"dns";
    envelope.event_type = (char *)"dns.transaction.observed";

    query_header.id = 0x1234;
    query_header.qdcount = 1;

    query.header = &query_header;

    dns_transaction.query = &query;
    dns_transaction.role = CLOUDFLOW__V1__DNS_LEG__DNS_LEG_CLIENT_FACING;
    dns_transaction.rtt_nanos = 1500000;
    dns_transaction.rtt_valid = 1;
    dns_transaction.client_ip = (char *)"192.0.2.10";
    dns_transaction.client_port = 5353;
    dns_transaction.server_ip = (char *)"192.0.2.53";

    event.envelope = &envelope;
    event.payload_case = CLOUDFLOW__V1__CLOUD_FLOW_EVENT__PAYLOAD_DNS_TRANSACTION;
    event.dns_transaction = &dns_transaction;

    packed_len = cloudflow__v1__cloud_flow_event__get_packed_size(&event);
    CU_ASSERT_TRUE(packed_len > 0);

    buf = malloc(packed_len);
    CU_ASSERT_PTR_NOT_NULL_FATAL(buf);

    CU_ASSERT_EQUAL(cloudflow__v1__cloud_flow_event__pack(&event, buf), packed_len);

    unpacked = cloudflow__v1__cloud_flow_event__unpack(NULL, packed_len, buf);
    CU_ASSERT_PTR_NOT_NULL_FATAL(unpacked);

    CU_ASSERT_PTR_NOT_NULL_FATAL(unpacked->envelope);
    CU_ASSERT_STRING_EQUAL(unpacked->envelope->event_id, envelope.event_id);

    /* Oneof discipline: dhcpv4_packet/dhcpv6_packet/dhcpv4_lease/dns_transaction
     * share storage (a C union), so payload_case -- not pointer nullness -- is
     * the authoritative discriminant that the DNS alternative was selected. */
    CU_ASSERT_EQUAL(unpacked->payload_case, CLOUDFLOW__V1__CLOUD_FLOW_EVENT__PAYLOAD_DNS_TRANSACTION);
    CU_ASSERT_NOT_EQUAL(unpacked->payload_case, CLOUDFLOW__V1__CLOUD_FLOW_EVENT__PAYLOAD_DHCPV4_PACKET);
    CU_ASSERT_PTR_NOT_NULL_FATAL(unpacked->dns_transaction);
    CU_ASSERT_PTR_NOT_NULL_FATAL(unpacked->dns_transaction->query);
    CU_ASSERT_PTR_NOT_NULL_FATAL(unpacked->dns_transaction->query->header);
    CU_ASSERT_EQUAL(unpacked->dns_transaction->query->header->id, query_header.id);
    CU_ASSERT_EQUAL(unpacked->dns_transaction->role, dns_transaction.role);
    CU_ASSERT_EQUAL(unpacked->dns_transaction->rtt_nanos, dns_transaction.rtt_nanos);
    CU_ASSERT_STRING_EQUAL(unpacked->dns_transaction->client_ip, dns_transaction.client_ip);
    CU_ASSERT_EQUAL(unpacked->dns_transaction->client_port, dns_transaction.client_port);
    CU_ASSERT_STRING_EQUAL(unpacked->dns_transaction->server_ip, dns_transaction.server_ip);

    cloudflow__v1__cloud_flow_event__free_unpacked(unpacked, NULL);
    free(buf);
}

int main(void)
{
    CU_pSuite suite;
    unsigned int failed;

    if (CU_initialize_registry() != CUE_SUCCESS)
        return (int)CU_get_error();

    suite = CU_add_suite("cf_codec (WP-02 round-trip)", NULL, NULL);
    if (!suite) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    if (!CU_add_test(suite, "EventEnvelope fields survive pack/unpack", test_envelope_roundtrip) ||
        !CU_add_test(suite, "DhcpV4PacketEvent oneof case survives pack/unpack", test_dhcpv4_payload_oneof_roundtrip) ||
        !CU_add_test(suite, "DnsTransactionEvent oneof case survives pack/unpack", test_dns_transaction_payload_oneof_roundtrip)) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();

    failed = CU_get_number_of_tests_failed();

    CU_cleanup_registry();

    return failed > 0 ? 1 : 0;
}
