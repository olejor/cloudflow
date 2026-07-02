#include "cf_event_id.h"

#include <string.h>

#include "sha256.h"

/* Hash a single field as a 4-byte big-endian length prefix followed by its
 * bytes, so that field boundaries in the overall digest can't collide
 * (see cf_event_id.h). */
static void cf_event_id_hash_field(sha256_ctx *ctx, const uint8_t *data, size_t len)
{
    uint8_t len_bytes[4];

    len_bytes[0] = (uint8_t)(len >> 24);
    len_bytes[1] = (uint8_t)(len >> 16);
    len_bytes[2] = (uint8_t)(len >> 8);
    len_bytes[3] = (uint8_t)(len);

    sha256_update(ctx, len_bytes, sizeof(len_bytes));

    if (len > 0)
        sha256_update(ctx, data, len);
}

void cf_event_id(char out[CF_EVENT_ID_LEN],
                  const char *source_host,
                  const char *capture_interface,
                  int64_t observed_time_unix_nano,
                  const uint8_t *frame, size_t frame_len)
{
    static const char hex_digits[] = "0123456789abcdef";
    sha256_ctx ctx;
    uint8_t digest[SHA256_DIGEST_SIZE];
    uint8_t time_bytes[8];
    uint64_t t = (uint64_t)observed_time_unix_nano;
    size_t i;

    if (!source_host)
        source_host = "";
    if (!capture_interface)
        capture_interface = "";

    for (i = 0; i < sizeof(time_bytes); i++)
        time_bytes[i] = (uint8_t)(t >> (8 * (7 - i)));

    sha256_init(&ctx);
    cf_event_id_hash_field(&ctx, (const uint8_t *)source_host, strlen(source_host));
    cf_event_id_hash_field(&ctx, (const uint8_t *)capture_interface, strlen(capture_interface));
    cf_event_id_hash_field(&ctx, time_bytes, sizeof(time_bytes));
    cf_event_id_hash_field(&ctx, frame, frame_len);
    sha256_final(&ctx, digest);

    for (i = 0; i < 16; i++) {
        out[i * 2] = hex_digits[digest[i] >> 4];
        out[i * 2 + 1] = hex_digits[digest[i] & 0x0fu];
    }
    out[32] = '\0';
}
