/* Byte-for-byte invariant test for the DHCP cBPF filter.
 *
 * When build_dhcp_bpf_filter() was split out of rx_reader.c and rebuilt on
 * libs/cloudflow-capture's shared cf_bpf assembler/primitives (synergy item
 * A2), the assembled program had to stay identical to the one the DHCP source
 * shipped before the move -- a kernel-side filter silently drops what it
 * rejects, so any drift is invisible in production. The golden below was
 * captured from the pre-move build; this test asserts the current
 * build_dhcp_bpf_filter() reproduces it exactly (instruction count and every
 * struct sock_filter word). */

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include <stdio.h>

#include <linux/filter.h>

#include "dhcp_bpf.h"

/* Golden: 49 instructions, captured from the DHCP filter as it was assembled
 * inside rx_reader.c before the cf_bpf extraction. */
static const struct sock_filter golden[] = {
    { 0x0028, 0, 0, 0x0000000c },
    { 0x0015, 2, 0, 0x00008100 },
    { 0x0015, 4, 0, 0x00000800 },
    { 0x0015, 14, 44, 0x000086dd },
    { 0x0028, 0, 0, 0x00000010 },
    { 0x0015, 21, 0, 0x00000800 },
    { 0x0015, 31, 41, 0x000086dd },
    { 0x0030, 0, 0, 0x00000017 },
    { 0x0015, 0, 39, 0x00000011 },
    { 0x0028, 0, 0, 0x00000014 },
    { 0x0045, 37, 0, 0x00001fff },
    { 0x00b1, 0, 0, 0x0000000e },
    { 0x0048, 0, 0, 0x0000000e },
    { 0x0015, 33, 0, 0x00000043 },
    { 0x0015, 32, 0, 0x00000044 },
    { 0x0048, 0, 0, 0x00000010 },
    { 0x0015, 30, 0, 0x00000043 },
    { 0x0015, 29, 30, 0x00000044 },
    { 0x0030, 0, 0, 0x00000014 },
    { 0x0015, 0, 28, 0x00000011 },
    { 0x0001, 0, 0, 0x00000036 },
    { 0x0048, 0, 0, 0x00000000 },
    { 0x0015, 24, 0, 0x00000222 },
    { 0x0015, 23, 0, 0x00000223 },
    { 0x0048, 0, 0, 0x00000002 },
    { 0x0015, 21, 0, 0x00000222 },
    { 0x0015, 20, 21, 0x00000223 },
    { 0x0030, 0, 0, 0x0000001b },
    { 0x0015, 0, 19, 0x00000011 },
    { 0x0028, 0, 0, 0x00000018 },
    { 0x0045, 17, 0, 0x00001fff },
    { 0x00b1, 0, 0, 0x00000012 },
    { 0x0048, 0, 0, 0x00000012 },
    { 0x0015, 13, 0, 0x00000043 },
    { 0x0015, 12, 0, 0x00000044 },
    { 0x0048, 0, 0, 0x00000014 },
    { 0x0015, 10, 0, 0x00000043 },
    { 0x0015, 9, 10, 0x00000044 },
    { 0x0030, 0, 0, 0x00000018 },
    { 0x0015, 0, 8, 0x00000011 },
    { 0x0001, 0, 0, 0x0000003a },
    { 0x0048, 0, 0, 0x00000000 },
    { 0x0015, 4, 0, 0x00000222 },
    { 0x0015, 3, 0, 0x00000223 },
    { 0x0048, 0, 0, 0x00000002 },
    { 0x0015, 1, 0, 0x00000222 },
    { 0x0015, 0, 1, 0x00000223 },
    { 0x0006, 0, 0, 0xffffffff },
    { 0x0006, 0, 0, 0x00000000 },
};

#define GOLDEN_N ((int)(sizeof(golden) / sizeof(golden[0])))

static void test_dhcp_bpf_byte_identical(void)
{
    struct sock_filter got[128];
    int n;
    int i;

    n = build_dhcp_bpf_filter(got, (int)(sizeof(got) / sizeof(got[0])));

    /* Same instruction count as the golden capture. */
    CU_ASSERT_EQUAL_FATAL(n, GOLDEN_N);

    /* Every struct sock_filter word (code/jt/jf/k) matches. */
    for (i = 0; i < n; i++) {
        CU_ASSERT_EQUAL(got[i].code, golden[i].code);
        CU_ASSERT_EQUAL(got[i].jt, golden[i].jt);
        CU_ASSERT_EQUAL(got[i].jf, golden[i].jf);
        CU_ASSERT_EQUAL(got[i].k, golden[i].k);
        if (got[i].code != golden[i].code || got[i].jt != golden[i].jt ||
            got[i].jf != golden[i].jf || got[i].k != golden[i].k) {
            fprintf(stderr, "insn %d mismatch: got {0x%04x,%u,%u,0x%08x} want {0x%04x,%u,%u,0x%08x}\n",
                    i, got[i].code, got[i].jt, got[i].jf, got[i].k,
                    golden[i].code, golden[i].jt, golden[i].jf, golden[i].k);
        }
    }
}

int main(void)
{
    CU_pSuite suite;
    unsigned int failed;

    if (CU_initialize_registry() != CUE_SUCCESS)
        return (int)CU_get_error();

    suite = CU_add_suite("cloudflow-source-dhcp dhcp_bpf", NULL, NULL);
    if (!suite) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    if (!CU_add_test(suite, "DHCP cBPF filter is byte-for-byte identical to the golden capture",
                      test_dhcp_bpf_byte_identical)) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();

    failed = CU_get_number_of_tests_failed();

    CU_cleanup_registry();

    return failed > 0 ? 1 : 0;
}
