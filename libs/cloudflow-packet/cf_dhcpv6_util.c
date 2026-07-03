/* Shared helpers for the WP-07 DHCPv6 parser: bounds-checked byte readers,
 * string/bytes builders for protobuf-c fields, the parser-warning list, and
 * the top-level raw-option accumulator. See cf_dhcpv6_internal.h for the
 * contracts these implement (a self-contained mirror of the equivalent
 * WP-06 helpers in cf_dhcpv4_util.c -- see that file's header comment and
 * cf_dhcpv6_internal.h's header comment for why this is not a shared file).
 */

#include "cf_dhcpv6_internal.h"

#include <stdlib.h>
#include <string.h>

#include "cf_ipfmt.h"

/* ---- bounds-checked byte readers -------------------------------------- */

int cf_dhcpv6__get_u8(const uint8_t *d, size_t len, size_t off, uint8_t *out)
{
    if (off + 1 > len)
        return 0;
    *out = d[off];
    return 1;
}

int cf_dhcpv6__get_be16(const uint8_t *d, size_t len, size_t off, uint16_t *out)
{
    if (off + 2 > len)
        return 0;
    *out = (uint16_t)(((uint16_t)d[off] << 8) | (uint16_t)d[off + 1]);
    return 1;
}

int cf_dhcpv6__get_be24(const uint8_t *d, size_t len, size_t off, uint32_t *out)
{
    if (off + 3 > len)
        return 0;
    *out = ((uint32_t)d[off] << 16) | ((uint32_t)d[off + 1] << 8) | (uint32_t)d[off + 2];
    return 1;
}

int cf_dhcpv6__get_be32(const uint8_t *d, size_t len, size_t off, uint32_t *out)
{
    if (off + 4 > len)
        return 0;
    *out = ((uint32_t)d[off] << 24) | ((uint32_t)d[off + 1] << 16) |
           ((uint32_t)d[off + 2] << 8) | (uint32_t)d[off + 3];
    return 1;
}

/* ---- string/bytes helpers ---------------------------------------------- */

char *cf_dhcpv6__dup_str(const char *s)
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

char *cf_dhcpv6__dup_strn(const uint8_t *bytes, size_t len)
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

int cf_dhcpv6__is_printable(const uint8_t *bytes, size_t len)
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

char *cf_dhcpv6__hex_encode(const uint8_t *bytes, size_t len)
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

void cf_dhcpv6__set_bytes(ProtobufCBinaryData *out, const uint8_t *bytes, size_t len)
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

char *cf_dhcpv6__format_ipv6(const uint8_t ip[16])
{
    char buf[46];

    cf_format_ip(buf, 6, ip);
    return cf_dhcpv6__dup_str(buf);
}

/* ---- parser warnings ---------------------------------------------------- */

void cf_dhcpv6__warn_list_init(cf_dhcpv6_warn_list_t *list)
{
    list->items = NULL;
    list->count = 0;
    list->cap = 0;
}

static int warn_list_grow(cf_dhcpv6_warn_list_t *list)
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

void cf_dhcpv6__warn(cf_dhcpv6_warn_list_t *list, const char *code,
                      const char *message, const char *field_path,
                      const uint8_t *ctx, size_t ctx_len)
{
    Cloudflow__V1__ParserWarning *w;

    if (!warn_list_grow(list))
        return;

    w = calloc(1, sizeof(*w));
    if (!w)
        return;
    cloudflow__v1__parser_warning__init(w);

    w->code = cf_dhcpv6__dup_str(code);
    w->message = cf_dhcpv6__dup_str(message);
    w->field_path = cf_dhcpv6__dup_str(field_path);
    if (ctx_len > 16)
        ctx_len = 16;
    cf_dhcpv6__set_bytes(&w->raw_context, ctx, ctx_len);

    list->items[list->count++] = w;
}

void cf_dhcpv6__warn_list_take(cf_dhcpv6_warn_list_t *list, size_t *n_out,
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

/* ---- top-level raw-option accumulator ----------------------------------- */

void cf_dhcpv6__raw_item_list_init(cf_dhcpv6_raw_item_list_t *list)
{
    list->items = NULL;
    list->count = 0;
    list->cap = 0;
}

int cf_dhcpv6__raw_item_list_append(cf_dhcpv6_raw_item_list_t *list, uint32_t code,
                                     uint32_t ordinal, const uint8_t *value,
                                     size_t value_len, int malformed)
{
    cf_dhcpv6_raw_item_t *it;

    if (list->count == list->cap) {
        size_t new_cap = list->cap == 0 ? 8 : list->cap * 2;
        cf_dhcpv6_raw_item_t *ni = realloc(list->items, new_cap * sizeof(*ni));
        if (!ni)
            return 0;
        list->items = ni;
        list->cap = new_cap;
    }

    it = &list->items[list->count];
    it->code = code;
    it->ordinal = ordinal;
    it->malformed = malformed;
    it->value_len = value_len;
    it->value = NULL;
    if (value_len > 0 && value) {
        it->value = malloc(value_len);
        if (it->value)
            memcpy(it->value, value, value_len);
        else
            it->value_len = 0;
    }

    list->count++;
    return 1;
}

void cf_dhcpv6__raw_item_list_free(cf_dhcpv6_raw_item_list_t *list)
{
    size_t i;

    for (i = 0; i < list->count; i++)
        free(list->items[i].value);
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->cap = 0;
}
