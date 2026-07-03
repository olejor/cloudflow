#ifndef CF_DHCPV6_INTERNAL_H
#define CF_DHCPV6_INTERNAL_H

/* Shared plumbing between cf_dhcpv6.c (header + raw option walk) and
 * cf_dhcpv6_decode.c (DhcpV6DecodedOptions builder). Not installed/public --
 * only used within libs/cloudflow-packet.
 *
 * Deliberately a self-contained mirror of cf_dhcpv4_internal.h / cf_dhcpv4_util.c
 * rather than a #include of them: the two parsers are independent WPs that
 * happen to need the same small set of bounds-checked-reader / protobuf-c
 * string-and-bytes / ParserWarning-list helpers, and duplicating ~150 lines
 * of tiny static helpers keeps WP-07 from taking a compile-time dependency
 * on WP-06's internal (non-installed) header. See
 * docs/design/02-packet-and-parsing.md's "Shared parser conventions".
 */

#include <stddef.h>
#include <stdint.h>

#include "cloudflow/v1/dhcp.pb-c.h"

/* ---- small bounds-checked byte readers -------------------------------- */

int cf_dhcpv6__get_u8(const uint8_t *d, size_t len, size_t off, uint8_t *out);
int cf_dhcpv6__get_be16(const uint8_t *d, size_t len, size_t off, uint16_t *out);
int cf_dhcpv6__get_be24(const uint8_t *d, size_t len, size_t off, uint32_t *out);
int cf_dhcpv6__get_be32(const uint8_t *d, size_t len, size_t off, uint32_t *out);

/* ---- string/bytes helpers ---------------------------------------------- */

/* Always returns a non-NULL, heap-owned (or the immutable
 * protobuf_c_empty_string sentinel) string suitable for a protobuf-c
 * message's `char *` field. */
char *cf_dhcpv6__dup_str(const char *s);
char *cf_dhcpv6__dup_strn(const uint8_t *bytes, size_t len);

/* True if every byte in [bytes, bytes+len) is printable ASCII (0x20-0x7e). */
int cf_dhcpv6__is_printable(const uint8_t *bytes, size_t len);

/* Lowercase hex encoding, no separators, e.g. {0x02,0x00} -> "0200". */
char *cf_dhcpv6__hex_encode(const uint8_t *bytes, size_t len);

/* Copies `len` bytes into a fresh malloc'd buffer for a ProtobufCBinaryData
 * (data=NULL/len=0 when len==0, matching protobuf-c's own convention). */
void cf_dhcpv6__set_bytes(ProtobufCBinaryData *out, const uint8_t *bytes, size_t len);

/* Formats a 16-byte IPv6 address as an owned text-representation string via
 * cf_ipfmt.h. */
char *cf_dhcpv6__format_ipv6(const uint8_t ip[16]);

/* ---- parser warnings ----------------------------------------------------
 *
 * A small growable array of Cloudflow__V1__ParserWarning* accumulated for
 * the top-level DhcpV6PacketEvent.parser_warnings list.
 */
typedef struct {
    Cloudflow__V1__ParserWarning **items;
    size_t count;
    size_t cap;
} cf_dhcpv6_warn_list_t;

void cf_dhcpv6__warn_list_init(cf_dhcpv6_warn_list_t *list);
/* raw_context is clipped to 16 bytes per the shared parser conventions.
 * `ctx`/`ctx_len` may be NULL/0 if there is no useful raw context to
 * attach. */
void cf_dhcpv6__warn(cf_dhcpv6_warn_list_t *list, const char *code,
                      const char *message, const char *field_path,
                      const uint8_t *ctx, size_t ctx_len);
/* Hands ownership of the accumulated warnings to (n_out,items_out); resets
 * the list to empty. If the list is empty, *items_out is left NULL and
 * *n_out is 0 (protobuf-c's convention for an empty repeated field). */
void cf_dhcpv6__warn_list_take(cf_dhcpv6_warn_list_t *list, size_t *n_out,
                                Cloudflow__V1__ParserWarning ***items_out);

/* ---- raw (top-level) option accumulator --------------------------------
 *
 * Built once by cf_dhcpv6.c's option walk and consumed both to populate
 * DhcpV6PacketEvent.raw_options and (read-only, before the list is freed)
 * by cf_dhcpv6_decode.c's cf_dhcpv6__build_decoded() to find/decode the
 * options it cares about (client/server DUID, IA_NA/IA_TA, ORO, vendor
 * class, vendor-specific info). `value` points into memory owned by the
 * list (freed by cf_dhcpv6__raw_item_list_free()), not by the caller.
 */
typedef struct {
    uint32_t code;
    uint32_t ordinal;
    uint8_t *value; /* owned by the list; NULL when value_len == 0 */
    size_t value_len;
    int malformed;
} cf_dhcpv6_raw_item_t;

typedef struct {
    cf_dhcpv6_raw_item_t *items;
    size_t count;
    size_t cap;
} cf_dhcpv6_raw_item_list_t;

void cf_dhcpv6__raw_item_list_init(cf_dhcpv6_raw_item_list_t *list);
int cf_dhcpv6__raw_item_list_append(cf_dhcpv6_raw_item_list_t *list, uint32_t code,
                                     uint32_t ordinal, const uint8_t *value,
                                     size_t value_len, int malformed);
void cf_dhcpv6__raw_item_list_free(cf_dhcpv6_raw_item_list_t *list);

/* ---- decoded-options builder (cf_dhcpv6_decode.c) ----------------------- */

/* Builds *out (a fresh, __init()-ed DhcpV6DecodedOptions) from the top-level
 * raw options walked by cf_dhcpv6.c. Appends any decode-level warnings
 * (insufficient length, IA/IAADDR truncation, etc.) to `warnings` with
 * field_path values like "decoded.assigned_addresses" /
 * "decoded.vendor_options.suboptions".
 */
void cf_dhcpv6__build_decoded(const cf_dhcpv6_raw_item_t *items, size_t n_items,
                               Cloudflow__V1__DhcpV6DecodedOptions **out,
                               cf_dhcpv6_warn_list_t *warnings);

#endif
