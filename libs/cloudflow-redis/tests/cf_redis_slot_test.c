/* Acceptance tests for cf_redis_slot: the Redis Cluster key-hashing used by
 * the routing layer. Pure logic, no server needed. Values are the canonical
 * vectors from the Redis cluster spec and `CLUSTER KEYSLOT`, so a regression in
 * the CRC16 table or the hash-tag rule is caught here rather than by MOVED
 * storms against a live cluster. */

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>
#include <string.h>

#include "cf_redis_slot.h"

#define SLOT(k) cf_redis_key_slot((k), strlen(k))

static void test_crc16_canonical(void)
{
    /* The reference vector every CRC16-CCITT/XMODEM implementation pins. */
    CU_ASSERT_EQUAL(cf_redis_crc16("123456789", 9), 0x31C3);
    CU_ASSERT_EQUAL(cf_redis_crc16("", 0), 0x0000);
}

static void test_keyslot_known_values(void)
{
    /* `CLUSTER KEYSLOT foo` == 12182 on any real cluster. */
    CU_ASSERT_EQUAL(SLOT("foo"), 12182u);
    /* `CLUSTER KEYSLOT user1000` == 3443. */
    CU_ASSERT_EQUAL(SLOT("user1000"), 3443u);
    CU_ASSERT(SLOT("foo") < CF_REDIS_NUM_SLOTS);
}

static void test_hashtag_colocates(void)
{
    /* A "{tag}" makes only the tag hash, so "{foo}bar" and "bar{foo}" and the
     * bare "foo" all land in the same slot. */
    CU_ASSERT_EQUAL(SLOT("{foo}bar"), SLOT("foo"));
    CU_ASSERT_EQUAL(SLOT("bar{foo}"), SLOT("foo"));
    CU_ASSERT_EQUAL(SLOT("{user1000}.following"), SLOT("user1000"));
    CU_ASSERT_EQUAL(SLOT("{user1000}.followers"), SLOT("{user1000}.following"));
}

static void test_hashtag_edge_cases(void)
{
    /* Empty "{}" -> the whole key is hashed (the braces are not special). */
    CU_ASSERT_EQUAL(SLOT("{}foo"), cf_redis_crc16("{}foo", 5) % CF_REDIS_NUM_SLOTS);
    /* '}' before '{' -> whole key. */
    CU_ASSERT_EQUAL(SLOT("}foo{"), cf_redis_crc16("}foo{", 5) % CF_REDIS_NUM_SLOTS);
    /* Only the first '{'..'}' pair matters: "{{bar}}zap" hashes "{bar". */
    CU_ASSERT_EQUAL(SLOT("{{bar}}zap"), cf_redis_crc16("{bar", 4) % CF_REDIS_NUM_SLOTS);
    /* No braces at all -> whole key. */
    CU_ASSERT_EQUAL(SLOT("plainkey"), cf_redis_crc16("plainkey", 8) % CF_REDIS_NUM_SLOTS);
}

static void test_wire_streams_span_slots(void)
{
    /* The default wire stream names are NOT co-located: this is exactly why a
     * multi-stream XREADGROUP needs per-slot handling on a cluster. */
    unsigned v4 = SLOT("cloudflow:v1:wire:dhcpv4");
    unsigned dns = SLOT("cloudflow:v1:wire:dns");
    CU_ASSERT_NOT_EQUAL(v4, dns);

    /* Adding a shared "{wire}" hash tag co-locates them, if an operator opts in. */
    CU_ASSERT_EQUAL(SLOT("cloudflow:v1:{wire}:dhcpv4"), SLOT("cloudflow:v1:{wire}:dns"));
}

int cf_redis_slot_register_suite(void);
int cf_redis_slot_register_suite(void)
{
    CU_pSuite s = CU_add_suite("cf_redis_slot", NULL, NULL);
    if (!s)
        return -1;
    if (!CU_add_test(s, "crc16 canonical vector", test_crc16_canonical) ||
        !CU_add_test(s, "keyslot known values", test_keyslot_known_values) ||
        !CU_add_test(s, "hash tag co-locates keys", test_hashtag_colocates) ||
        !CU_add_test(s, "hash tag edge cases", test_hashtag_edge_cases) ||
        !CU_add_test(s, "wire streams span slots", test_wire_streams_span_slots))
        return -1;
    return 0;
}

int main(void)
{
    unsigned int failed;

    if (CU_initialize_registry() != CUE_SUCCESS)
        return (int)CU_get_error();
    if (cf_redis_slot_register_suite() != 0) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    failed = CU_get_number_of_tests_failed();
    CU_cleanup_registry();
    return failed > 0 ? 1 : 0;
}
