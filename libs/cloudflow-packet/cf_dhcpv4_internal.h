#ifndef CF_DHCPV4_INTERNAL_H
#define CF_DHCPV4_INTERNAL_H

/* Shared plumbing between cf_dhcpv4.c (fixed header + raw option walk +
 * interpretation) and cf_dhcpv4_decode.c (DhcpV4DecodedOptions builder).
 * Not installed/public -- only used within libs/cloudflow-packet.
 */

#include <stddef.h>
#include <stdint.h>

#include "cloudflow/v1/dhcp.pb-c.h"

/* ---- small bounds-checked byte readers -------------------------------- */

int cf_dhcpv4__get_u8(const uint8_t *d, size_t len, size_t off, uint8_t *out);
int cf_dhcpv4__get_be16(const uint8_t *d, size_t len, size_t off, uint16_t *out);
int cf_dhcpv4__get_be32(const uint8_t *d, size_t len, size_t off, uint32_t *out);

/* ---- string/bytes helpers ---------------------------------------------- */

/* Always returns a non-NULL, heap-owned (or the immutable
 * protobuf_c_empty_string sentinel) string suitable for a protobuf-c
 * message's `char *` field -- callers never need to NULL-check the result
 * before assigning it into a generated struct. */
char *cf_dhcpv4__dup_str(const char *s);
char *cf_dhcpv4__dup_strn(const uint8_t *bytes, size_t len);

/* True if every byte in [bytes, bytes+len) is printable ASCII (0x20-0x7e). */
int cf_dhcpv4__is_printable(const uint8_t *bytes, size_t len);

/* Lowercase hex encoding, no separators, e.g. {0x02,0x00} -> "0200". */
char *cf_dhcpv4__hex_encode(const uint8_t *bytes, size_t len);

/* Copies `len` bytes into a fresh malloc'd buffer for a ProtobufCBinaryData
 * (data=NULL/len=0 when len==0, matching protobuf-c's own convention). */
void cf_dhcpv4__set_bytes(ProtobufCBinaryData *out, const uint8_t *bytes, size_t len);

/* Formats a 4-byte big-endian IPv4 address as an owned decimal-dotted
 * string ("192.0.2.1"), via cf_ipfmt.h. */
char *cf_dhcpv4__format_ipv4(const uint8_t ip[4]);

/* ---- parser warnings ----------------------------------------------------
 *
 * A small growable array of Cloudflow__V1__ParserWarning* used both for the
 * top-level DhcpV4PacketEvent.parser_warnings list and (separately) for
 * DhcpV4VendorSpecificInformation.parser_warnings.
 */
typedef struct {
    Cloudflow__V1__ParserWarning **items;
    size_t count;
    size_t cap;
} cf_dhcpv4_warn_list_t;

void cf_dhcpv4__warn_list_init(cf_dhcpv4_warn_list_t *list);
/* raw_context is clipped to 16 bytes per the WP-06 spec. `ctx`/`ctx_len` may
 * be NULL/0 if there is no useful raw context to attach. */
void cf_dhcpv4__warn(cf_dhcpv4_warn_list_t *list, const char *code,
                      const char *message, const char *field_path,
                      const uint8_t *ctx, size_t ctx_len);
/* Hands ownership of the accumulated warnings to (n_out,items_out); resets
 * the list to empty. If the list is empty, *items_out is left NULL and
 * *n_out is 0 (protobuf-c's convention for an empty repeated field). */
void cf_dhcpv4__warn_list_take(cf_dhcpv4_warn_list_t *list, size_t *n_out,
                                Cloudflow__V1__ParserWarning ***items_out);

/* ---- concatenated (RFC 3396) option data by code ----------------------- */

typedef struct {
    uint32_t code;
    uint8_t *data;   /* owned; NULL when len==0 */
    size_t len;
} cf_dhcpv4_concat_t;

typedef struct {
    cf_dhcpv4_concat_t *items;
    size_t count;
    size_t cap;
} cf_dhcpv4_concat_map_t;

void cf_dhcpv4__concat_map_init(cf_dhcpv4_concat_map_t *map);
void cf_dhcpv4__concat_map_append(cf_dhcpv4_concat_map_t *map, uint32_t code,
                                   const uint8_t *data, size_t len);
/* Returns NULL if `code` never appeared; otherwise the concatenated bytes
 * (owned by the map -- do not free) and sets *len_out. A present-but-empty
 * option (e.g. a bare option 82 flag with no suboptions) returns a non-NULL
 * pointer to a zero-length allocation is not guaranteed -- callers must
 * check *len_out, not just the pointer, and treat NULL-with-not-found vs.
 * NULL-with-zero-length the same way (both "nothing to decode"). */
const uint8_t *cf_dhcpv4__concat_map_get(const cf_dhcpv4_concat_map_t *map,
                                          uint32_t code, size_t *len_out);
/* True if `code` was seen at all (even as a zero-length option), regardless
 * of whether it accumulated any bytes -- lets decode logic tell "option
 * absent" apart from "option present with empty value". */
int cf_dhcpv4__concat_map_has(const cf_dhcpv4_concat_map_t *map, uint32_t code);
void cf_dhcpv4__concat_map_free(cf_dhcpv4_concat_map_t *map);

/* ---- decoded-options builder (cf_dhcpv4_decode.c) ----------------------- */

/* Builds *out (a fresh, __init()-ed DhcpV4DecodedOptions) from the
 * concatenated per-code option data in `cm`. Appends any decode-level
 * warnings (insufficient length, bad compression pointer, etc.) to
 * `warnings` with field_path values like "decoded.subnet_mask" /
 * "decoded.classless_static_routes[2]" (option 43's own suboption warnings
 * go to the returned message's own vendor_specific_information.parser_warnings
 * instead, per the proto's dedicated field for that).
 */
void cf_dhcpv4__build_decoded(const cf_dhcpv4_concat_map_t *cm,
                               Cloudflow__V1__DhcpV4DecodedOptions **out,
                               cf_dhcpv4_warn_list_t *warnings);

#endif
