#ifndef CF_EVENT_ID_H
#define CF_EVENT_ID_H

#include <stddef.h>
#include <stdint.h>

/* Deterministic event identity (D5 in docs/architecture.md): the
 * lowercase-hex, 128-bit (16 byte) truncation of a SHA-256 digest over
 *
 *   (source_host, capture_interface, observed_time_unix_nano, frame)
 *
 * Each field is length-prefixed (a 4-byte big-endian byte count) before
 * its bytes are hashed, so that e.g. ("ab", "c") and ("a", "bc") -- which
 * would concatenate to the same bytes -- hash to different digests.
 * Replaying the same capture therefore always yields the same event_id. */

#define CF_EVENT_ID_LEN 33 /* 32 hex chars + NUL */

void cf_event_id(char out[CF_EVENT_ID_LEN],
                  const char *source_host,
                  const char *capture_interface,
                  int64_t observed_time_unix_nano,
                  const uint8_t *frame, size_t frame_len);

#endif
