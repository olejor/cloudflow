#ifndef CF_REDIS_SLOT_H
#define CF_REDIS_SLOT_H

#include <stddef.h>
#include <stdint.h>

/* Redis Cluster hashes every key into one of 16384 slots; each master owns a
 * contiguous set of slots. A command's key must be sent to the node owning
 * that key's slot (else the node replies -MOVED/-ASK). These helpers compute
 * the slot exactly as Redis does, so the routing layer can pick the right
 * node. See https://redis.io/docs/reference/cluster-spec/ ("Key distribution
 * model" and "Keys hash tags"). */

#define CF_REDIS_NUM_SLOTS 16384u

/* CRC16-CCITT (the "XMODEM" variant) over `buf`, as Redis defines it in
 * src/crc16.c. Exposed mainly so tests can pin the canonical
 * CRC16("123456789") == 0x31C3 vector. */
uint16_t cf_redis_crc16(const char *buf, size_t len);

/* The cluster slot for `key`: CRC16(key) % 16384, honoring the hash-tag rule.
 * If the key contains a '{' followed later by a '}' with a non-empty substring
 * between them, only that substring is hashed (so "{u1}.a" and "{u1}.b"
 * co-locate); otherwise the whole key is hashed. An empty "{}" or a '}' before
 * any '{' means the whole key is hashed, per the spec. */
uint16_t cf_redis_key_slot(const char *key, size_t len);

#endif
