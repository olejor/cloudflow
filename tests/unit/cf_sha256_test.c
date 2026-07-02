/* NIST SHA-256 test vectors: empty string, "abc", and the 448-bit
 * multi-block message from FIPS 180-4 / the NIST CAVP examples. */

#include <CUnit/CUnit.h>
#include <string.h>

#include "cf_core_test.h"
#include "sha256.h"

static void hex_encode(const uint8_t *digest, size_t len, char *out)
{
    static const char hex_digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < len; i++) {
        out[i * 2] = hex_digits[digest[i] >> 4];
        out[i * 2 + 1] = hex_digits[digest[i] & 0x0fu];
    }
    out[len * 2] = '\0';
}

static void assert_sha256_hex(const char *msg, const char *expected_hex)
{
    sha256_ctx ctx;
    uint8_t digest[SHA256_DIGEST_SIZE];
    char hex[SHA256_DIGEST_SIZE * 2 + 1];

    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)msg, strlen(msg));
    sha256_final(&ctx, digest);

    hex_encode(digest, sizeof(digest), hex);

    CU_ASSERT_STRING_EQUAL(hex, expected_hex);
}

static void test_sha256_empty_string(void)
{
    assert_sha256_hex("",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

static void test_sha256_abc(void)
{
    assert_sha256_hex("abc",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

static void test_sha256_448bit(void)
{
    assert_sha256_hex(
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

/* Also exercise the streaming interface (multiple update() calls) against
 * the same 448-bit vector, split across several calls including one that
 * crosses the 64-byte block boundary. */
static void test_sha256_streaming_matches_single_shot(void)
{
    static const char msg[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha256_ctx ctx;
    uint8_t digest[SHA256_DIGEST_SIZE];
    char hex[SHA256_DIGEST_SIZE * 2 + 1];
    size_t len = strlen(msg);
    size_t chunk1 = 10;
    size_t chunk2 = 40; /* crosses the 64-byte block boundary */

    CU_ASSERT_FATAL(chunk1 + chunk2 < len);

    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)msg, chunk1);
    sha256_update(&ctx, (const uint8_t *)msg + chunk1, chunk2);
    sha256_update(&ctx, (const uint8_t *)msg + chunk1 + chunk2, len - chunk1 - chunk2);
    sha256_final(&ctx, digest);

    hex_encode(digest, sizeof(digest), hex);

    CU_ASSERT_STRING_EQUAL(hex,
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

int cf_sha256_register_suite(void)
{
    CU_pSuite suite = CU_add_suite("sha256 NIST vectors", NULL, NULL);

    if (!suite)
        return -1;

    if (!CU_add_test(suite, "empty string", test_sha256_empty_string))
        return -1;
    if (!CU_add_test(suite, "'abc'", test_sha256_abc))
        return -1;
    if (!CU_add_test(suite, "448-bit multi-block message", test_sha256_448bit))
        return -1;
    if (!CU_add_test(suite, "streaming update() matches single-shot", test_sha256_streaming_matches_single_shot))
        return -1;

    return 0;
}
