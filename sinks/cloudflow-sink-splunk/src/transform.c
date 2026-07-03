#include "transform.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "yyjson.h"

/* ---- base64 (standard alphabet, padded) --------------------------------- */

static const char b64_alpha[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Encodes `len` bytes into a malloc'd NUL-terminated base64 string. */
static char *base64_encode(const uint8_t *data, size_t len)
{
    size_t out_len = 4 * ((len + 2) / 3);
    char *out = malloc(out_len + 1);
    size_t i, o = 0;

    if (!out)
        return NULL;

    for (i = 0; i + 2 < len; i += 3) {
        uint32_t n = ((uint32_t)data[i] << 16) | ((uint32_t)data[i + 1] << 8) | data[i + 2];
        out[o++] = b64_alpha[(n >> 18) & 0x3f];
        out[o++] = b64_alpha[(n >> 12) & 0x3f];
        out[o++] = b64_alpha[(n >> 6) & 0x3f];
        out[o++] = b64_alpha[n & 0x3f];
    }
    if (i < len) {
        uint32_t n = (uint32_t)data[i] << 16;
        int rem = (int)(len - i); /* 1 or 2 */
        if (rem == 2)
            n |= (uint32_t)data[i + 1] << 8;
        out[o++] = b64_alpha[(n >> 18) & 0x3f];
        out[o++] = b64_alpha[(n >> 12) & 0x3f];
        out[o++] = (rem == 2) ? b64_alpha[(n >> 6) & 0x3f] : '=';
        out[o++] = '=';
    }
    out[o] = '\0';
    return out;
}

/* ---- generic protobuf-c message -> yyjson (MessageToDict semantics) ------ */

static yyjson_mut_val *build_message(yyjson_mut_doc *doc, const ProtobufCMessage *msg,
                                     int include_raw_payload);

static const char *enum_name(const ProtobufCEnumDescriptor *desc, int value)
{
    unsigned i;

    if (desc) {
        for (i = 0; i < desc->n_values; i++) {
            if (desc->values[i].value == value)
                return desc->values[i].name;
        }
    }
    return NULL;
}

/* Reads a single scalar (or message) element at `ptr` of the given proto type
 * and returns its JSON value. */
static yyjson_mut_val *build_scalar(yyjson_mut_doc *doc, ProtobufCType type,
                                    const void *descriptor, const void *ptr,
                                    int include_raw_payload)
{
    char numbuf[32];

    switch (type) {
    case PROTOBUF_C_TYPE_INT32:
    case PROTOBUF_C_TYPE_SINT32:
    case PROTOBUF_C_TYPE_SFIXED32:
        return yyjson_mut_int(doc, *(const int32_t *)ptr);
    case PROTOBUF_C_TYPE_UINT32:
    case PROTOBUF_C_TYPE_FIXED32:
        return yyjson_mut_uint(doc, *(const uint32_t *)ptr);
    case PROTOBUF_C_TYPE_INT64:
    case PROTOBUF_C_TYPE_SINT64:
    case PROTOBUF_C_TYPE_SFIXED64:
        /* 64-bit ints are JSON strings in protobuf JSON. */
        snprintf(numbuf, sizeof(numbuf), "%" PRId64, *(const int64_t *)ptr);
        return yyjson_mut_strcpy(doc, numbuf);
    case PROTOBUF_C_TYPE_UINT64:
    case PROTOBUF_C_TYPE_FIXED64:
        snprintf(numbuf, sizeof(numbuf), "%" PRIu64, *(const uint64_t *)ptr);
        return yyjson_mut_strcpy(doc, numbuf);
    case PROTOBUF_C_TYPE_FLOAT:
        return yyjson_mut_real(doc, (double)*(const float *)ptr);
    case PROTOBUF_C_TYPE_DOUBLE:
        return yyjson_mut_real(doc, *(const double *)ptr);
    case PROTOBUF_C_TYPE_BOOL:
        return yyjson_mut_bool(doc, *(const protobuf_c_boolean *)ptr != 0);
    case PROTOBUF_C_TYPE_ENUM: {
        int v = *(const int *)ptr;
        const char *name = enum_name((const ProtobufCEnumDescriptor *)descriptor, v);
        if (name)
            return yyjson_mut_strcpy(doc, name);
        return yyjson_mut_int(doc, v); /* unknown enum -> numeric, per proto JSON */
    }
    case PROTOBUF_C_TYPE_STRING: {
        const char *s = *(const char *const *)ptr;
        return yyjson_mut_strcpy(doc, s ? s : "");
    }
    case PROTOBUF_C_TYPE_BYTES: {
        const ProtobufCBinaryData *bd = (const ProtobufCBinaryData *)ptr;
        char *b64 = base64_encode(bd->data, bd->len);
        yyjson_mut_val *val;
        if (!b64)
            return NULL;
        val = yyjson_mut_strcpy(doc, b64);
        free(b64);
        return val;
    }
    case PROTOBUF_C_TYPE_MESSAGE: {
        const ProtobufCMessage *sub = *(const ProtobufCMessage *const *)ptr;
        if (!sub)
            return NULL;
        return build_message(doc, sub, include_raw_payload);
    }
    default:
        return NULL;
    }
}

static size_t scalar_elem_size(ProtobufCType type)
{
    switch (type) {
    case PROTOBUF_C_TYPE_INT32:
    case PROTOBUF_C_TYPE_SINT32:
    case PROTOBUF_C_TYPE_SFIXED32:
    case PROTOBUF_C_TYPE_UINT32:
    case PROTOBUF_C_TYPE_FIXED32:
        return 4;
    case PROTOBUF_C_TYPE_INT64:
    case PROTOBUF_C_TYPE_SINT64:
    case PROTOBUF_C_TYPE_SFIXED64:
    case PROTOBUF_C_TYPE_UINT64:
    case PROTOBUF_C_TYPE_FIXED64:
        return 8;
    case PROTOBUF_C_TYPE_FLOAT:
        return 4;
    case PROTOBUF_C_TYPE_DOUBLE:
        return 8;
    case PROTOBUF_C_TYPE_BOOL:
        return sizeof(protobuf_c_boolean);
    case PROTOBUF_C_TYPE_ENUM:
        return 4;
    case PROTOBUF_C_TYPE_STRING:
        return sizeof(char *);
    case PROTOBUF_C_TYPE_BYTES:
        return sizeof(ProtobufCBinaryData);
    case PROTOBUF_C_TYPE_MESSAGE:
        return sizeof(ProtobufCMessage *);
    default:
        return 0;
    }
}

/* True if a proto3 singular scalar/message field holds its default (and so is
 * omitted by MessageToDict). */
static int is_default_singular(const ProtobufCFieldDescriptor *f, const ProtobufCMessage *msg)
{
    const void *member = (const char *)msg + f->offset;

    switch (f->type) {
    case PROTOBUF_C_TYPE_INT32:
    case PROTOBUF_C_TYPE_SINT32:
    case PROTOBUF_C_TYPE_SFIXED32:
        return *(const int32_t *)member == 0;
    case PROTOBUF_C_TYPE_UINT32:
    case PROTOBUF_C_TYPE_FIXED32:
        return *(const uint32_t *)member == 0;
    case PROTOBUF_C_TYPE_INT64:
    case PROTOBUF_C_TYPE_SINT64:
    case PROTOBUF_C_TYPE_SFIXED64:
        return *(const int64_t *)member == 0;
    case PROTOBUF_C_TYPE_UINT64:
    case PROTOBUF_C_TYPE_FIXED64:
        return *(const uint64_t *)member == 0;
    case PROTOBUF_C_TYPE_FLOAT:
        return *(const float *)member == 0.0f;
    case PROTOBUF_C_TYPE_DOUBLE:
        return *(const double *)member == 0.0;
    case PROTOBUF_C_TYPE_BOOL:
        return *(const protobuf_c_boolean *)member == 0;
    case PROTOBUF_C_TYPE_ENUM:
        return *(const int *)member == 0;
    case PROTOBUF_C_TYPE_STRING: {
        const char *s = *(const char *const *)member;
        return s == NULL || s[0] == '\0';
    }
    case PROTOBUF_C_TYPE_BYTES: {
        const ProtobufCBinaryData *bd = (const ProtobufCBinaryData *)member;
        return bd->len == 0;
    }
    case PROTOBUF_C_TYPE_MESSAGE:
        return *(const ProtobufCMessage *const *)member == NULL;
    default:
        return 1;
    }
}

/* Sorting scratch entry. */
typedef struct {
    const char *key;
    yyjson_mut_val *val;
} kv_entry_t;

static int kv_cmp(const void *a, const void *b)
{
    const kv_entry_t *ka = a;
    const kv_entry_t *kb = b;
    return strcmp(ka->key, kb->key);
}

static yyjson_mut_val *build_message(yyjson_mut_doc *doc, const ProtobufCMessage *msg,
                                     int include_raw_payload)
{
    const ProtobufCMessageDescriptor *desc = msg->descriptor;
    yyjson_mut_val *obj = yyjson_mut_obj(doc);
    kv_entry_t *entries;
    size_t n_entries = 0;
    unsigned i;

    if (!obj)
        return NULL;
    if (desc->n_fields == 0)
        return obj;

    entries = malloc(desc->n_fields * sizeof(*entries));
    if (!entries)
        return NULL;

    for (i = 0; i < desc->n_fields; i++) {
        const ProtobufCFieldDescriptor *f = &desc->fields[i];
        const void *member = (const char *)msg + f->offset;
        yyjson_mut_val *val = NULL;

        /* raw_dhcp_payload is stripped from the HEC event unless configured. */
        if (!include_raw_payload && strcmp(f->name, "raw_dhcp_payload") == 0)
            continue;

        if (f->label == PROTOBUF_C_LABEL_REPEATED) {
            size_t count = *(const size_t *)((const char *)msg + f->quantifier_offset);
            const void *arr = *(const void *const *)member;
            size_t elem_size = scalar_elem_size(f->type);
            yyjson_mut_val *jarr;
            size_t j;

            if (count == 0)
                continue;
            jarr = yyjson_mut_arr(doc);
            if (!jarr)
                goto fail;
            for (j = 0; j < count; j++) {
                const void *elemptr = (const char *)arr + j * elem_size;
                yyjson_mut_val *ev =
                    build_scalar(doc, f->type, f->descriptor, elemptr, include_raw_payload);
                if (!ev)
                    goto fail;
                yyjson_mut_arr_add_val(jarr, ev);
            }
            val = jarr;
        } else if (f->flags & PROTOBUF_C_FIELD_FLAG_ONEOF) {
            uint32_t which = *(const uint32_t *)((const char *)msg + f->quantifier_offset);
            if (which != f->id)
                continue;
            val = build_scalar(doc, f->type, f->descriptor, member, include_raw_payload);
            if (!val)
                continue; /* oneof message set but NULL: treat as absent */
        } else {
            if (is_default_singular(f, msg))
                continue;
            val = build_scalar(doc, f->type, f->descriptor, member, include_raw_payload);
            if (!val)
                goto fail;
        }

        entries[n_entries].key = f->name;
        entries[n_entries].val = val;
        n_entries++;
    }

    qsort(entries, n_entries, sizeof(*entries), kv_cmp);
    for (i = 0; i < n_entries; i++)
        yyjson_mut_obj_add_val(doc, obj, entries[i].key, entries[i].val);

    free(entries);
    return obj;

fail:
    free(entries);
    return NULL;
}

/* Render observed_time_unix_nano as seconds with exactly 9 decimal places. */
static void format_hec_time(int64_t nanos, char *buf, size_t cap)
{
    const char *sign = "";
    uint64_t mag;
    uint64_t secs, frac;

    if (nanos < 0) {
        sign = "-";
        mag = (uint64_t)(-(nanos + 1)) + 1u; /* safe negation for INT64_MIN */
    } else {
        mag = (uint64_t)nanos;
    }
    secs = mag / 1000000000ull;
    frac = mag % 1000000000ull;
    snprintf(buf, cap, "%s%" PRIu64 ".%09" PRIu64, sign, secs, frac);
}

char *cf_transform_render_hec_line(const Cloudflow__V1__CloudFlowEvent *ev,
                                   const char *stream_name,
                                   const cf_splunk_config_t *splunk)
{
    yyjson_mut_doc *doc = NULL;
    yyjson_mut_val *root = NULL;
    yyjson_mut_val *event_obj = NULL;
    const Cloudflow__V1__EventEnvelope *env = ev ? ev->envelope : NULL;
    char st_buf[128];
    char time_buf[48];
    const char *sourcetype;
    const char *source;
    const char *host;
    char *out = NULL;

    if (!ev || !env)
        return NULL;

    doc = yyjson_mut_doc_new(NULL);
    if (!doc)
        return NULL;

    event_obj = build_message(doc, &ev->base, splunk->include_raw_payload);
    if (!event_obj)
        goto done;

    host = env->source_host ? env->source_host : "";
    source = (env->stream_name && env->stream_name[0]) ? env->stream_name
                                                       : (stream_name ? stream_name : "");
    sourcetype = cf_splunk_sourcetype_for(splunk, env->source_type ? env->source_type : "",
                                          st_buf, sizeof(st_buf));
    format_hec_time(env->observed_time_unix_nano, time_buf, sizeof(time_buf));

    root = yyjson_mut_obj(doc);
    if (!root)
        goto done;

    /* Keys are added in sorted order (event, host, index, source, sourcetype,
     * time) to match the Python --stdout sort_keys output. */
    yyjson_mut_obj_add_val(doc, root, "event", event_obj);
    yyjson_mut_obj_add_strcpy(doc, root, "host", host);
    if (splunk->index && splunk->index[0])
        yyjson_mut_obj_add_strcpy(doc, root, "index", splunk->index);
    yyjson_mut_obj_add_strcpy(doc, root, "source", source);
    yyjson_mut_obj_add_strcpy(doc, root, "sourcetype", sourcetype);
    /* time must render as a bare JSON number with all 9 decimals preserved. */
    yyjson_mut_obj_add_val(doc, root, "time", yyjson_mut_rawcpy(doc, time_buf));

    yyjson_mut_doc_set_root(doc, root);
    out = yyjson_mut_write(doc, YYJSON_WRITE_NOFLAG, NULL);

done:
    yyjson_mut_doc_free(doc);
    return out;
}
