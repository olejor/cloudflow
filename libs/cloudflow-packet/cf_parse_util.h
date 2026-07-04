#ifndef CF_PARSE_UTIL_H
#define CF_PARSE_UTIL_H

/* Protocol-neutral parser helpers (WP-DNS03 refactor item "B"): the
 * bounds-checked byte readers, protobuf-c string/bytes builders, and the
 * parser-warning list that were previously duplicated per protocol
 * (cf_dhcpv4__* / cf_dhcpv6__*). New protocol parsers (cf_dns.c, and later
 * TCP-DNS decode) build on these `cf_`-named generic versions instead of
 * copying the DHCP ones. The existing cf_dhcpv4__ / cf_dhcpv6__ copies are
 * left untouched -- this module is purely additive.
 *
 * Not installed/public -- only used within libs/cloudflow-packet.
 */

#include <stddef.h>
#include <stdint.h>

#include <protobuf-c/protobuf-c.h>

#include "cloudflow/v1/common.pb-c.h"

/* ---- bounds-checked byte readers ---------------------------------------
 *
 * Each reads a big-endian integer at offset `off` in the `len`-byte buffer
 * `d`, returning 1 on success and 0 if the read would run past `len` (in
 * which case *out is left untouched). Same contracts as cf_dhcpv4__get_*.
 */
int cf_get_u8(const uint8_t *d, size_t len, size_t off, uint8_t *out);
int cf_get_be16(const uint8_t *d, size_t len, size_t off, uint16_t *out);
int cf_get_be32(const uint8_t *d, size_t len, size_t off, uint32_t *out);

/* ---- string/bytes helpers ----------------------------------------------
 *
 * Always return a non-NULL, heap-owned string (or the immutable
 * protobuf_c_empty_string sentinel) suitable for a protobuf-c message's
 * `char *` field -- callers never need to NULL-check the result before
 * assigning it into a generated struct, and the generated
 * ..._free_unpacked() frees it correctly either way.
 */
char *cf_dup_str(const char *s);
char *cf_dup_strn(const uint8_t *bytes, size_t len);

/* True if every byte in [bytes, bytes+len) is printable ASCII (0x20-0x7e). */
int cf_is_printable(const uint8_t *bytes, size_t len);

/* Lowercase hex encoding, no separators, e.g. {0x02,0x00} -> "0200". */
char *cf_hex_encode(const uint8_t *bytes, size_t len);

/* Copies `len` bytes into a fresh malloc'd buffer for a ProtobufCBinaryData
 * (data=NULL/len=0 when len==0, matching protobuf-c's own convention). */
void cf_set_bytes(ProtobufCBinaryData *out, const uint8_t *bytes, size_t len);

/* ---- parser warnings ----------------------------------------------------
 *
 * A small growable array of Cloudflow__V1__ParserWarning*, mirroring
 * cf_dhcpv4_warn_list_t. Used to accumulate decode-level warnings that are
 * then handed to a repeated `parser_warnings` field.
 */
typedef struct {
    Cloudflow__V1__ParserWarning **items;
    size_t count;
    size_t cap;
} cf_warn_list_t;

void cf_warn_list_init(cf_warn_list_t *list);
/* Appends one warning. raw_context (ctx/ctx_len) is clipped to 16 bytes;
 * ctx/ctx_len may be NULL/0 when there is no useful raw context. */
void cf_warn(cf_warn_list_t *list, const char *code, const char *message,
             const char *field_path, const uint8_t *ctx, size_t ctx_len);
/* Hands ownership of the accumulated warnings to (n_out,items_out); resets
 * the list to empty. If the list is empty, *items_out is left NULL and
 * *n_out is 0 (protobuf-c's convention for an empty repeated field). */
void cf_warn_list_take(cf_warn_list_t *list, size_t *n_out,
                       Cloudflow__V1__ParserWarning ***items_out);

#endif
