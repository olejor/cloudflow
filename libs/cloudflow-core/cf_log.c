#include "cf_log.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define CF_LOG_LINE_MAX 4096
#define CF_LOG_FIELD_SCRATCH_MAX 1024
#define CF_LOG_KEY_SCRATCH_MAX 256
#define CF_LOG_SERVICE_MAX 128

static char g_service_name[CF_LOG_SERVICE_MAX] = "cloudflow";

static const char *cf_log_level_name(cf_log_level_t level)
{
    switch (level) {
    case CF_LOG_DEBUG:
        return "debug";
    case CF_LOG_INFO:
        return "info";
    case CF_LOG_WARN:
        return "warn";
    case CF_LOG_ERROR:
        return "error";
    default:
        return "unknown";
    }
}

static void cf_log_format_timestamp(char *buf, size_t buf_len)
{
    struct timespec ts;
    struct tm tmv;
    int ms;

    clock_gettime(CLOCK_REALTIME, &ts);
    gmtime_r(&ts.tv_sec, &tmv);
    ms = (int)((ts.tv_nsec / 1000000L) % 1000);

    snprintf(buf, buf_len, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
              tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
              tmv.tm_hour, tmv.tm_min, tmv.tm_sec, ms);
}

/* JSON-escape `src` into `dst` (a caller-owned buffer of size `dst_cap`).
 * Stops (without emitting a partial escape sequence or partial byte) if
 * `dst` fills up -- the result is always a well-formed, NUL-terminated
 * JSON string body, possibly truncated. Returns the number of bytes
 * written (excluding the NUL). */
static size_t cf_log_json_escape(char *dst, size_t dst_cap, const char *src)
{
    size_t len = 0;

    if (!src)
        src = "";

    if (dst_cap == 0)
        return 0;

    for (; *src != '\0'; src++) {
        unsigned char c = (unsigned char)*src;
        char ubuf[8];
        const char *esc = NULL;

        switch (c) {
        case '"':
            esc = "\\\"";
            break;
        case '\\':
            esc = "\\\\";
            break;
        case '\n':
            esc = "\\n";
            break;
        case '\r':
            esc = "\\r";
            break;
        case '\t':
            esc = "\\t";
            break;
        case '\b':
            esc = "\\b";
            break;
        case '\f':
            esc = "\\f";
            break;
        default:
            if (c < 0x20) {
                snprintf(ubuf, sizeof(ubuf), "\\u%04x", c);
                esc = ubuf;
            }
            break;
        }

        if (esc != NULL) {
            size_t elen = strlen(esc);

            if (len + elen + 1 > dst_cap)
                break;

            memcpy(dst + len, esc, elen);
            len += elen;
        } else {
            if (len + 1 + 1 > dst_cap)
                break;

            dst[len++] = (char)c;
        }
    }

    dst[len] = '\0';

    return len;
}

/* Append `prefix` followed by the JSON-escaped form of `raw_value` and a
 * closing quote to `line`, entirely or not at all: if the combined field
 * would not fit in `cap` bytes, `line`/`len` are left untouched and 0 is
 * returned. This is what keeps the output valid JSON even when a caller's
 * message/value is large enough to threaten truncation -- we only ever
 * drop whole fields, never half of one. */
static int cf_log_append_field(char *line, size_t cap, size_t *len,
                                const char *prefix, const char *raw_value,
                                char *scratch, size_t scratch_cap)
{
    size_t vlen = cf_log_json_escape(scratch, scratch_cap, raw_value);
    size_t plen = strlen(prefix);

    if (*len + plen + vlen + 1 > cap)
        return 0;

    memcpy(line + *len, prefix, plen);
    *len += plen;
    memcpy(line + *len, scratch, vlen);
    *len += vlen;
    line[(*len)++] = '"';

    return 1;
}

void cf_log_init(const char *service_name)
{
    if (!service_name)
        service_name = "cloudflow";

    snprintf(g_service_name, sizeof(g_service_name), "%s", service_name);
}

void cf_log(cf_log_level_t level, const char *msg, ...)
{
    char line[CF_LOG_LINE_MAX];
    char scratch[CF_LOG_FIELD_SCRATCH_MAX];
    char key_scratch[CF_LOG_KEY_SCRATCH_MAX];
    char prefix[CF_LOG_KEY_SCRATCH_MAX + 8];
    char ts_buf[80];
    size_t len;
    size_t cap = sizeof(line) - 3; /* reserve room for the unconditional "}\n\0" tail */
    va_list ap;

    cf_log_format_timestamp(ts_buf, sizeof(ts_buf));

    len = (size_t)snprintf(line, sizeof(line),
                             "{\"ts\":\"%s\",\"level\":\"%s\",\"service\":\"",
                             ts_buf, cf_log_level_name(level));
    if (len >= sizeof(line))
        len = sizeof(line) - 1;

    (void)cf_log_append_field(line, cap, &len, "", g_service_name, scratch, sizeof(scratch));
    (void)cf_log_append_field(line, cap, &len, ",\"msg\":\"", msg, scratch, sizeof(scratch));

    va_start(ap, msg);
    for (;;) {
        const char *key = va_arg(ap, const char *);
        const char *value;

        if (key == NULL)
            break;

        value = va_arg(ap, const char *);

        cf_log_json_escape(key_scratch, sizeof(key_scratch), key);
        snprintf(prefix, sizeof(prefix), ",\"%s\":\"", key_scratch);

        if (!cf_log_append_field(line, cap, &len, prefix, value, scratch, sizeof(scratch)))
            break; /* out of room: drop this and any further pairs, keep valid JSON */
    }
    va_end(ap);

    line[len++] = '}';
    line[len++] = '\n';
    line[len] = '\0';

    fwrite(line, 1, len, stderr);
    fflush(stderr);
}

const char *cf_log_i64(char *buf, size_t buf_len, int64_t value)
{
    snprintf(buf, buf_len, "%" PRId64, value);
    return buf;
}

const char *cf_log_u64(char *buf, size_t buf_len, uint64_t value)
{
    snprintf(buf, buf_len, "%" PRIu64, value);
    return buf;
}
