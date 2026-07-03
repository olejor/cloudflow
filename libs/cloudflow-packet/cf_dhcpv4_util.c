/* Shared helpers for the WP-06 DHCPv4 parser: bounds-checked byte readers,
 * string/bytes builders for protobuf-c fields, the parser-warning list, and
 * the RFC 3396 "concatenate same-code option fragments" map. See
 * cf_dhcpv4_internal.h for the contracts these implement.
 */

#include "cf_dhcpv4_internal.h"

#include <stdlib.h>
#include <string.h>

#include "cf_ipfmt.h"

/* ---- bounds-checked byte readers -------------------------------------- */

int cf_dhcpv4__get_u8(const uint8_t *d, size_t len, size_t off, uint8_t *out)
{
    if (off + 1 > len)
        return 0;
    *out = d[off];
    return 1;
}

int cf_dhcpv4__get_be16(const uint8_t *d, size_t len, size_t off, uint16_t *out)
{
    if (off + 2 > len)
        return 0;
    *out = (uint16_t)(((uint16_t)d[off] << 8) | (uint16_t)d[off + 1]);
    return 1;
}

int cf_dhcpv4__get_be32(const uint8_t *d, size_t len, size_t off, uint32_t *out)
{
    if (off + 4 > len)
        return 0;
    *out = ((uint32_t)d[off] << 24) | ((uint32_t)d[off + 1] << 16) |
           ((uint32_t)d[off + 2] << 8) | (uint32_t)d[off + 3];
    return 1;
}

/* ---- string/bytes helpers ---------------------------------------------- */

char *cf_dhcpv4__dup_str(const char *s)
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

char *cf_dhcpv4__dup_strn(const uint8_t *bytes, size_t len)
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

int cf_dhcpv4__is_printable(const uint8_t *bytes, size_t len)
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

char *cf_dhcpv4__hex_encode(const uint8_t *bytes, size_t len)
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

void cf_dhcpv4__set_bytes(ProtobufCBinaryData *out, const uint8_t *bytes, size_t len)
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

char *cf_dhcpv4__format_ipv4(const uint8_t ip[4])
{
    char buf[46];
    uint8_t ip16[16];

    memset(ip16, 0, sizeof(ip16));
    memcpy(ip16, ip, 4);
    cf_format_ip(buf, 4, ip16);
    return cf_dhcpv4__dup_str(buf);
}

/* ---- parser warnings ---------------------------------------------------- */

void cf_dhcpv4__warn_list_init(cf_dhcpv4_warn_list_t *list)
{
    list->items = NULL;
    list->count = 0;
    list->cap = 0;
}

static int warn_list_grow(cf_dhcpv4_warn_list_t *list)
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

void cf_dhcpv4__warn(cf_dhcpv4_warn_list_t *list, const char *code,
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

    w->code = cf_dhcpv4__dup_str(code);
    w->message = cf_dhcpv4__dup_str(message);
    w->field_path = cf_dhcpv4__dup_str(field_path);
    if (ctx_len > 16)
        ctx_len = 16;
    cf_dhcpv4__set_bytes(&w->raw_context, ctx, ctx_len);

    list->items[list->count++] = w;
}

void cf_dhcpv4__warn_list_take(cf_dhcpv4_warn_list_t *list, size_t *n_out,
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

/* ---- RFC 3396 concatenated-by-code option map --------------------------- */

void cf_dhcpv4__concat_map_init(cf_dhcpv4_concat_map_t *map)
{
    map->items = NULL;
    map->count = 0;
    map->cap = 0;
}

static cf_dhcpv4_concat_t *concat_map_find_or_add(cf_dhcpv4_concat_map_t *map,
                                                    uint32_t code)
{
    size_t i;
    cf_dhcpv4_concat_t *new_items;
    size_t new_cap;

    for (i = 0; i < map->count; i++) {
        if (map->items[i].code == code)
            return &map->items[i];
    }

    if (map->count == map->cap) {
        new_cap = map->cap == 0 ? 8 : map->cap * 2;
        new_items = realloc(map->items, new_cap * sizeof(*new_items));
        if (!new_items)
            return NULL;
        map->items = new_items;
        map->cap = new_cap;
    }

    map->items[map->count].code = code;
    map->items[map->count].data = NULL;
    map->items[map->count].len = 0;
    return &map->items[map->count++];
}

void cf_dhcpv4__concat_map_append(cf_dhcpv4_concat_map_t *map, uint32_t code,
                                   const uint8_t *data, size_t len)
{
    cf_dhcpv4_concat_t *entry;
    uint8_t *grown;

    entry = concat_map_find_or_add(map, code);
    if (!entry)
        return;
    if (len == 0)
        return;

    grown = realloc(entry->data, entry->len + len);
    if (!grown)
        return;
    memcpy(grown + entry->len, data, len);
    entry->data = grown;
    entry->len += len;
}

const uint8_t *cf_dhcpv4__concat_map_get(const cf_dhcpv4_concat_map_t *map,
                                          uint32_t code, size_t *len_out)
{
    size_t i;

    for (i = 0; i < map->count; i++) {
        if (map->items[i].code == code) {
            *len_out = map->items[i].len;
            return map->items[i].data;
        }
    }
    *len_out = 0;
    return NULL;
}

int cf_dhcpv4__concat_map_has(const cf_dhcpv4_concat_map_t *map, uint32_t code)
{
    size_t i;

    for (i = 0; i < map->count; i++) {
        if (map->items[i].code == code)
            return 1;
    }
    return 0;
}

void cf_dhcpv4__concat_map_free(cf_dhcpv4_concat_map_t *map)
{
    size_t i;

    for (i = 0; i < map->count; i++)
        free(map->items[i].data);
    free(map->items);
    map->items = NULL;
    map->count = 0;
    map->cap = 0;
}
