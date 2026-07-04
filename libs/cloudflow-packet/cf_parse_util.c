/* Protocol-neutral parser helpers -- see cf_parse_util.h for the contracts.
 * These are the generic, `cf_`-named versions of the byte readers,
 * string/bytes builders, and warning list that cf_dhcpv4_util.c /
 * cf_dhcpv6_util.c each carry a protocol-scoped copy of; new parsers
 * (cf_dns.c) use these instead of duplicating them again.
 */

#include "cf_parse_util.h"

#include <stdlib.h>
#include <string.h>

/* ---- bounds-checked byte readers -------------------------------------- */

int cf_get_u8(const uint8_t *d, size_t len, size_t off, uint8_t *out)
{
    if (off + 1 > len)
        return 0;
    *out = d[off];
    return 1;
}

int cf_get_be16(const uint8_t *d, size_t len, size_t off, uint16_t *out)
{
    if (off + 2 > len)
        return 0;
    *out = (uint16_t)(((uint16_t)d[off] << 8) | (uint16_t)d[off + 1]);
    return 1;
}

int cf_get_be32(const uint8_t *d, size_t len, size_t off, uint32_t *out)
{
    if (off + 4 > len)
        return 0;
    *out = ((uint32_t)d[off] << 24) | ((uint32_t)d[off + 1] << 16) |
           ((uint32_t)d[off + 2] << 8) | (uint32_t)d[off + 3];
    return 1;
}

/* ---- string/bytes helpers ---------------------------------------------- */

char *cf_dup_str(const char *s)
{
    size_t n;
    char *out;

    if (!s || s[0] == '\0')
        return (char *)protobuf_c_empty_string;

    n = strlen(s);
    out = malloc(n + 1);
    if (!out)
        return (char *)protobuf_c_empty_string;
    memcpy(out, s, n + 1);
    return out;
}

char *cf_dup_strn(const uint8_t *bytes, size_t len)
{
    char *out;

    if (!bytes || len == 0)
        return (char *)protobuf_c_empty_string;

    out = malloc(len + 1);
    if (!out)
        return (char *)protobuf_c_empty_string;
    memcpy(out, bytes, len);
    out[len] = '\0';
    return out;
}

int cf_is_printable(const uint8_t *bytes, size_t len)
{
    size_t i;

    if (len == 0)
        return 0;
    for (i = 0; i < len; i++) {
        if (bytes[i] < 0x20 || bytes[i] > 0x7e)
            return 0;
    }
    return 1;
}

char *cf_hex_encode(const uint8_t *bytes, size_t len)
{
    static const char hexd[] = "0123456789abcdef";
    char *out;
    size_t i;

    if (!bytes || len == 0)
        return (char *)protobuf_c_empty_string;

    out = malloc(len * 2 + 1);
    if (!out)
        return (char *)protobuf_c_empty_string;
    for (i = 0; i < len; i++) {
        out[2 * i] = hexd[bytes[i] >> 4];
        out[2 * i + 1] = hexd[bytes[i] & 0x0f];
    }
    out[len * 2] = '\0';
    return out;
}

void cf_set_bytes(ProtobufCBinaryData *out, const uint8_t *bytes, size_t len)
{
    if (!bytes || len == 0) {
        out->data = NULL;
        out->len = 0;
        return;
    }
    out->data = malloc(len);
    if (!out->data) {
        out->len = 0;
        return;
    }
    memcpy(out->data, bytes, len);
    out->len = len;
}

/* ---- parser warnings ---------------------------------------------------- */

void cf_warn_list_init(cf_warn_list_t *list)
{
    list->items = NULL;
    list->count = 0;
    list->cap = 0;
}

static int warn_list_grow(cf_warn_list_t *list)
{
    size_t new_cap;
    Cloudflow__V1__ParserWarning **new_items;

    if (list->count < list->cap)
        return 1;

    new_cap = list->cap == 0 ? 4 : list->cap * 2;
    new_items = realloc(list->items, new_cap * sizeof(*new_items));
    if (!new_items)
        return 0;
    list->items = new_items;
    list->cap = new_cap;
    return 1;
}

void cf_warn(cf_warn_list_t *list, const char *code, const char *message,
             const char *field_path, const uint8_t *ctx, size_t ctx_len)
{
    Cloudflow__V1__ParserWarning *w;

    if (!warn_list_grow(list))
        return;

    w = calloc(1, sizeof(*w));
    if (!w)
        return;
    cloudflow__v1__parser_warning__init(w);

    w->code = cf_dup_str(code);
    w->message = cf_dup_str(message);
    w->field_path = cf_dup_str(field_path);
    if (ctx_len > 16)
        ctx_len = 16;
    cf_set_bytes(&w->raw_context, ctx, ctx_len);

    list->items[list->count++] = w;
}

void cf_warn_list_take(cf_warn_list_t *list, size_t *n_out,
                       Cloudflow__V1__ParserWarning ***items_out)
{
    if (list->count == 0) {
        free(list->items);
        *n_out = 0;
        *items_out = NULL;
    } else {
        *n_out = list->count;
        *items_out = list->items;
    }
    list->items = NULL;
    list->count = 0;
    list->cap = 0;
}
