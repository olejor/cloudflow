/* sha256.h
 *
 * Minimal SHA-256 implementation of the FIPS 180-4 message-digest
 * algorithm. Clean-room implementation written directly from the FIPS
 * 180-4 specification (Secure Hash Standard, NIST, August 2015) -- the
 * round constants and initial hash values below are the standard's
 * published constants, not copied from any particular codebase.
 *
 * To the extent possible under law, the author(s) have dedicated all
 * copyright and related and neighboring rights to this file to the public
 * domain worldwide. This file is distributed without any warranty. See
 * <https://creativecommons.org/publicdomain/zero/1.0/>.
 */

#ifndef CF_SHA256_H
#define CF_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_BLOCK_SIZE 64u  /* bytes per compression block */
#define SHA256_DIGEST_SIZE 32u /* bytes in the final digest */

typedef struct {
    uint32_t state[8];
    uint64_t total_len;              /* total message length in bytes */
    uint8_t buffer[SHA256_BLOCK_SIZE];
    size_t buffer_len;               /* bytes currently buffered (< 64) */
} sha256_ctx;

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len);
void sha256_final(sha256_ctx *ctx, uint8_t digest[SHA256_DIGEST_SIZE]);

#endif
