/* D5 event-id acceptance criteria: stable across repeated calls, sensitive
 * to every input field, and correctly length-prefixed so field boundaries
 * can't collide (the classic ("ab","c") vs ("a","bc") case). */

#include <CUnit/CUnit.h>
#include <string.h>

#include "cf_core_test.h"
#include "cf_event_id.h"

static const uint8_t frame_a[] = { 0x01, 0x02, 0x03, 0x04 };
static const uint8_t frame_b[] = { 0x01, 0x02, 0x03, 0x05 };

static void test_event_id_stable_across_calls(void)
{
    char id1[CF_EVENT_ID_LEN];
    char id2[CF_EVENT_ID_LEN];

    cf_event_id(id1, "host-a", "eth0", 1234567890, frame_a, sizeof(frame_a));
    cf_event_id(id2, "host-a", "eth0", 1234567890, frame_a, sizeof(frame_a));

    CU_ASSERT_EQUAL(strlen(id1), 32u);
    CU_ASSERT_STRING_EQUAL(id1, id2);
}

static void test_event_id_lowercase_hex(void)
{
    char id[CF_EVENT_ID_LEN];
    size_t i;

    cf_event_id(id, "host-a", "eth0", 1234567890, frame_a, sizeof(frame_a));

    CU_ASSERT_EQUAL(strlen(id), 32u);
    for (i = 0; i < strlen(id); i++) {
        char c = id[i];
        int is_lower_hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');

        CU_ASSERT_TRUE(is_lower_hex);
    }
}

static void test_event_id_sensitive_to_source_host(void)
{
    char id1[CF_EVENT_ID_LEN];
    char id2[CF_EVENT_ID_LEN];

    cf_event_id(id1, "host-a", "eth0", 1234567890, frame_a, sizeof(frame_a));
    cf_event_id(id2, "host-b", "eth0", 1234567890, frame_a, sizeof(frame_a));

    CU_ASSERT_STRING_NOT_EQUAL(id1, id2);
}

static void test_event_id_sensitive_to_capture_interface(void)
{
    char id1[CF_EVENT_ID_LEN];
    char id2[CF_EVENT_ID_LEN];

    cf_event_id(id1, "host-a", "eth0", 1234567890, frame_a, sizeof(frame_a));
    cf_event_id(id2, "host-a", "eth1", 1234567890, frame_a, sizeof(frame_a));

    CU_ASSERT_STRING_NOT_EQUAL(id1, id2);
}

static void test_event_id_sensitive_to_observed_time(void)
{
    char id1[CF_EVENT_ID_LEN];
    char id2[CF_EVENT_ID_LEN];

    cf_event_id(id1, "host-a", "eth0", 1234567890, frame_a, sizeof(frame_a));
    cf_event_id(id2, "host-a", "eth0", 1234567891, frame_a, sizeof(frame_a));

    CU_ASSERT_STRING_NOT_EQUAL(id1, id2);
}

static void test_event_id_sensitive_to_frame_bytes(void)
{
    char id1[CF_EVENT_ID_LEN];
    char id2[CF_EVENT_ID_LEN];

    cf_event_id(id1, "host-a", "eth0", 1234567890, frame_a, sizeof(frame_a));
    cf_event_id(id2, "host-a", "eth0", 1234567890, frame_b, sizeof(frame_b));

    CU_ASSERT_STRING_NOT_EQUAL(id1, id2);
}

static void test_event_id_sensitive_to_frame_length(void)
{
    char id1[CF_EVENT_ID_LEN];
    char id2[CF_EVENT_ID_LEN];

    cf_event_id(id1, "host-a", "eth0", 1234567890, frame_a, sizeof(frame_a));
    cf_event_id(id2, "host-a", "eth0", 1234567890, frame_a, sizeof(frame_a) - 1);

    CU_ASSERT_STRING_NOT_EQUAL(id1, id2);
}

/* The length-prefix boundary case: concatenating source_host="ab" with
 * capture_interface="c" gives the same raw bytes ("abc") as
 * source_host="a" with capture_interface="bc". Without length-prefixing
 * these would collide. */
static void test_event_id_length_prefix_boundary(void)
{
    char id1[CF_EVENT_ID_LEN];
    char id2[CF_EVENT_ID_LEN];

    cf_event_id(id1, "ab", "c", 1234567890, frame_a, sizeof(frame_a));
    cf_event_id(id2, "a", "bc", 1234567890, frame_a, sizeof(frame_a));

    CU_ASSERT_STRING_NOT_EQUAL(id1, id2);
}

int cf_event_id_register_suite(void)
{
    CU_pSuite suite = CU_add_suite("cf_event_id (D5)", NULL, NULL);

    if (!suite)
        return -1;

    if (!CU_add_test(suite, "stable across repeated calls", test_event_id_stable_across_calls))
        return -1;
    if (!CU_add_test(suite, "lowercase hex, 32 chars", test_event_id_lowercase_hex))
        return -1;
    if (!CU_add_test(suite, "sensitive to source_host", test_event_id_sensitive_to_source_host))
        return -1;
    if (!CU_add_test(suite, "sensitive to capture_interface", test_event_id_sensitive_to_capture_interface))
        return -1;
    if (!CU_add_test(suite, "sensitive to observed_time_unix_nano", test_event_id_sensitive_to_observed_time))
        return -1;
    if (!CU_add_test(suite, "sensitive to frame bytes", test_event_id_sensitive_to_frame_bytes))
        return -1;
    if (!CU_add_test(suite, "sensitive to frame length", test_event_id_sensitive_to_frame_length))
        return -1;
    if (!CU_add_test(suite, "length-prefix boundary: (ab,c) vs (a,bc)", test_event_id_length_prefix_boundary))
        return -1;

    return 0;
}
