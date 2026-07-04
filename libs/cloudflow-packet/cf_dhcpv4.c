/* WP-06 DHCPv4 parser: fixed BOOTP header, raw option wire walk (including
 * option-52 overload into sname/file and RFC 3396 long-option fragment
 * tracking), and the derived DhcpV4Interpretation. The decoded-option
 * builder (option-by-option semantic decode) lives in cf_dhcpv4_decode.c;
 * shared helpers live in cf_dhcpv4_util.c. See
 * docs/dhcp-source.md for the spec this implements, and
 * import/network_dhcp_collector/src/main.c's process_dhcpv4 /
 * src/test.c's variant for the TLV-walk shape this is lifted from (pad/end
 * handling, memcpy discipline) -- extended here with bounds-checked
 * resync-on-malformed, source-field tracking, and full protobuf output.
 *
 * Never trusts lengths: every option/field read is checked against the
 * remaining buffer before use. A malformed option marks itself
 * (DhcpV4Option.malformed = true), emits a ParserWarning with up to 16
 * bytes of raw_context, and parsing resumes at the best available point --
 * for a length overrun that point is "nothing further in this source field
 * is trustworthy", so that field's walk stops there (the packet as a whole,
 * and any other source field, is still fully parsed).
 */

#include "cf_dhcpv4.h"
#include "cf_dhcpv4_internal.h"
#include "cf_dhcpv4_optnames.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cf_ipfmt.h"

/* ---- BOOTP fixed-header layout ------------------------------------------ */

#define BOOTP_OP_OFF      0
#define BOOTP_HTYPE_OFF   1
#define BOOTP_HLEN_OFF    2
#define BOOTP_HOPS_OFF    3
#define BOOTP_XID_OFF     4
#define BOOTP_SECS_OFF    8
#define BOOTP_FLAGS_OFF   10
#define BOOTP_CIADDR_OFF  12
#define BOOTP_YIADDR_OFF  16
#define BOOTP_SIADDR_OFF  20
#define BOOTP_GIADDR_OFF  24
#define BOOTP_CHADDR_OFF  28
#define BOOTP_CHADDR_LEN  16
#define BOOTP_SNAME_OFF   44
#define BOOTP_SNAME_LEN   64
#define BOOTP_FILE_OFF    108
#define BOOTP_FILE_LEN    128
#define BOOTP_FIXED_LEN   236 /* op..file, no magic cookie/options */
#define BOOTP_COOKIE_OFF  236
#define BOOTP_COOKIE_LEN  4
#define BOOTP_OPTIONS_OFF 240

static const uint8_t DHCP_MAGIC_COOKIE[4] = {99, 130, 83, 99};

/* ---- raw option accumulator --------------------------------------------- */

typedef struct {
    uint32_t code;
    Cloudflow__V1__DhcpV4Option__SourceField source_field;
    uint32_t ordinal;
    uint8_t *value; /* owned; NULL when value_len == 0 */
    size_t value_len;
    int malformed;
    int long_option_fragment; /* filled in once all fields have been walked */
} raw_item_t;

typedef struct {
    raw_item_t *items;
    size_t count;
    size_t cap;
} raw_item_list_t;

static void raw_item_list_init(raw_item_list_t *list)
{
    list->items = NULL;
    list->count = 0;
    list->cap = 0;
}

static int raw_item_list_append(raw_item_list_t *list, uint32_t code,
                                 Cloudflow__V1__DhcpV4Option__SourceField sf,
                                 uint32_t ordinal, const uint8_t *value,
                                 size_t value_len, int malformed)
{
    raw_item_t *it;

    if (list->count == list->cap) {
        size_t new_cap = list->cap == 0 ? 8 : list->cap * 2;
        raw_item_t *ni = realloc(list->items, new_cap * sizeof(*ni));
        if (!ni)
            return 0;
        list->items = ni;
        list->cap = new_cap;
    }

    it = &list->items[list->count];
    it->code = code;
    it->source_field = sf;
    it->ordinal = ordinal;
    it->malformed = malformed;
    it->long_option_fragment = 0;
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

static void raw_item_list_free(raw_item_list_t *list)
{
    size_t i;

    for (i = 0; i < list->count; i++)
        free(list->items[i].value);
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->cap = 0;
}

/* Walks one source field's option bytes (the "options" field, or the
 * "file"/"sname" fields when option 52 overload says they hold options
 * too), appending each option found to `list` (a single list shared across
 * all three source fields, so field_path "raw_options[N]" in emitted
 * warnings matches the option's final index in the packed message) and to
 * the RFC 3396 concatenation map `cm`. `overload_out`, if non-NULL, is set
 * to the value of option 52 if one is found here (only meaningful when
 * walking the primary "options" field, per RFC 2132 9.3).
 */
static void walk_options_field(const uint8_t *field, size_t field_len,
                                Cloudflow__V1__DhcpV4Option__SourceField source_field,
                                raw_item_list_t *list, cf_dhcpv4_concat_map_t *cm,
                                cf_dhcpv4_warn_list_t *warnings, int *overload_out)
{
    size_t pos = 0;
    uint32_t ordinal = 0;
    char path[40];

    while (pos < field_len) {
        uint8_t code = field[pos];

        if (code == 0) { /* pad */
            pos++;
            continue;
        }
        if (code == 255) /* end of this field's options */
            break;

        if (pos + 2 > field_len) {
            /* Tag present but the length byte itself is missing. */
            snprintf(path, sizeof(path), "raw_options[%zu]", list->count);
            cf_dhcpv4__warn(warnings, "opt_missing_length",
                             "option tag present but truncated before its length byte",
                             path, &code, 1);
            raw_item_list_append(list, code, source_field, ordinal, NULL, 0, 1);
            cf_dhcpv4__concat_map_append(cm, code, NULL, 0);
            break; /* nothing reliable remains in this field */
        }

        {
            uint8_t declared_len = field[pos + 1];
            size_t avail = field_len - (pos + 2);
            size_t use_len = declared_len;
            int malformed = 0;
            const uint8_t *value_ptr = field + pos + 2;

            if (declared_len > avail) {
                use_len = avail;
                malformed = 1;
            }

            snprintf(path, sizeof(path), "raw_options[%zu]", list->count);
            raw_item_list_append(list, code, source_field, ordinal, value_ptr,
                                  use_len, malformed);
            cf_dhcpv4__concat_map_append(cm, code, value_ptr, use_len);

            if (malformed) {
                cf_dhcpv4__warn(warnings, "opt_len_overrun",
                                 "option length exceeds remaining bytes in this field",
                                 path, value_ptr, use_len);
            }

            if (code == 52 && overload_out != NULL && use_len >= 1)
                *overload_out = value_ptr[0];

            ordinal++;

            if (malformed)
                break; /* best resync: rest of this field is untrustworthy */

            pos += 2 + use_len;
        }
    }
}

/* ---- fixed header -------------------------------------------------------- */

static int maybe_all_zero(const uint8_t *b, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (b[i] != 0)
            return 0;
    }
    return 1;
}

/* sname/file are only surfaced as *_text when they hold a clean, printable
 * C string (NUL-terminated with everything after the NUL also zero, or
 * printable with no embedded NUL at all); otherwise the field is left at
 * its proto3 default ("") and only the raw bytes are exposed. This avoids
 * mis-rendering option-overloaded binary data (which starts with a small
 * option-code byte, almost never printable) as text. */
static char *maybe_text_field(const uint8_t *field, size_t field_len)
{
    size_t nul = field_len;
    size_t i;

    for (i = 0; i < field_len; i++) {
        if (field[i] == 0) {
            nul = i;
            break;
        }
    }
    if (nul == 0)
        return NULL;
    if (!cf_dhcpv4__is_printable(field, nul))
        return NULL;
    if (nul < field_len && !maybe_all_zero(field + nul, field_len - nul))
        return NULL;
    return cf_dhcpv4__dup_strn(field, nul);
}

static Cloudflow__V1__DhcpV4Header *build_header(const uint8_t *payload, size_t len)
{
    Cloudflow__V1__DhcpV4Header *hdr = calloc(1, sizeof(*hdr));
    uint8_t u8v;
    uint16_t u16v;
    uint32_t u32v;
    char *text;

    if (!hdr)
        return NULL;
    cloudflow__v1__dhcp_v4_header__init(hdr);

    cf_dhcpv4__get_u8(payload, len, BOOTP_OP_OFF, &u8v);
    hdr->op = u8v;
    cf_dhcpv4__get_u8(payload, len, BOOTP_HTYPE_OFF, &u8v);
    hdr->htype = u8v;
    cf_dhcpv4__get_u8(payload, len, BOOTP_HLEN_OFF, &u8v);
    hdr->hlen = u8v;
    cf_dhcpv4__get_u8(payload, len, BOOTP_HOPS_OFF, &u8v);
    hdr->hops = u8v;

    cf_dhcpv4__get_be32(payload, len, BOOTP_XID_OFF, &u32v);
    hdr->xid = u32v;
    cf_dhcpv4__get_be16(payload, len, BOOTP_SECS_OFF, &u16v);
    hdr->secs = u16v;
    cf_dhcpv4__get_be16(payload, len, BOOTP_FLAGS_OFF, &u16v);
    hdr->flags = u16v;

    hdr->ciaddr = cf_dhcpv4__format_ipv4(payload + BOOTP_CIADDR_OFF);
    hdr->yiaddr = cf_dhcpv4__format_ipv4(payload + BOOTP_YIADDR_OFF);
    hdr->siaddr = cf_dhcpv4__format_ipv4(payload + BOOTP_SIADDR_OFF);
    hdr->giaddr = cf_dhcpv4__format_ipv4(payload + BOOTP_GIADDR_OFF);

    cf_dhcpv4__set_bytes(&hdr->chaddr_raw, payload + BOOTP_CHADDR_OFF, BOOTP_CHADDR_LEN);
    if (hdr->htype == 1 && hdr->hlen == 6) {
        char macbuf[18];
        cf_format_mac(macbuf, payload + BOOTP_CHADDR_OFF);
        hdr->chaddr_mac = cf_dhcpv4__dup_str(macbuf);
    }

    cf_dhcpv4__set_bytes(&hdr->sname_raw, payload + BOOTP_SNAME_OFF, BOOTP_SNAME_LEN);
    text = maybe_text_field(payload + BOOTP_SNAME_OFF, BOOTP_SNAME_LEN);
    if (text)
        hdr->sname_text = text;

    cf_dhcpv4__set_bytes(&hdr->file_raw, payload + BOOTP_FILE_OFF, BOOTP_FILE_LEN);
    text = maybe_text_field(payload + BOOTP_FILE_OFF, BOOTP_FILE_LEN);
    if (text)
        hdr->file_text = text;

    hdr->magic_cookie_present = 0;
    if (len >= BOOTP_OPTIONS_OFF &&
        memcmp(payload + BOOTP_COOKIE_OFF, DHCP_MAGIC_COOKIE, BOOTP_COOKIE_LEN) == 0) {
        hdr->magic_cookie_present = 1;
    }

    return hdr;
}

/* ---- interpretation ------------------------------------------------------ */

static const char *event_type_for_message_type(
    Cloudflow__V1__DhcpV4DecodedOptions__MessageType mt)
{
    switch (mt) {
    case CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__DISCOVER:
        return "dhcpv4.discover.observed";
    case CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__OFFER:
        return "dhcpv4.offer.observed";
    case CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__REQUEST:
        return "dhcpv4.request.observed";
    case CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__DECLINE:
        return "dhcpv4.decline.observed";
    case CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__ACK:
        return "dhcpv4.ack.observed";
    case CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__NAK:
        return "dhcpv4.nak.observed";
    case CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__RELEASE:
        return "dhcpv4.release.observed";
    case CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__INFORM:
        return "dhcpv4.inform.observed";
    case CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__FORCERENEW:
        return "dhcpv4.forcerenew.observed";
    case CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__LEASEQUERY:
        return "dhcpv4.leasequery.observed";
    case CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__LEASEUNASSIGNED:
        return "dhcpv4.leaseunassigned.observed";
    case CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__LEASEUNKNOWN:
        return "dhcpv4.leaseunknown.observed";
    case CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__LEASEACTIVE:
        return "dhcpv4.leaseactive.observed";
    case CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__MESSAGE_TYPE_UNSPECIFIED:
    default:
        return "dhcpv4.packet.observed";
    }
}

static Cloudflow__V1__DhcpV4Interpretation *
build_interpretation(const Cloudflow__V1__DhcpV4Header *hdr,
                      const Cloudflow__V1__DhcpV4DecodedOptions *decoded,
                      const char *event_type)
{
    Cloudflow__V1__DhcpV4Interpretation *interp = calloc(1, sizeof(*interp));
    char *client_hex = NULL;

    if (!interp)
        return NULL;
    cloudflow__v1__dhcp_v4_interpretation__init(interp);

    interp->event_type = cf_dhcpv4__dup_str(event_type);

    if (decoded->client_identifier_raw.len > 0) {
        client_hex = cf_dhcpv4__hex_encode(decoded->client_identifier_raw.data,
                                            decoded->client_identifier_raw.len);
    }

    /* normalized_client_key: client-id (hex) if present, else chaddr MAC,
     * else "" (e.g. a non-Ethernet htype/hlen with no client-id option). */
    if (client_hex)
        interp->normalized_client_key = cf_dhcpv4__dup_str(client_hex);
    else if (hdr->chaddr_mac[0] != '\0')
        interp->normalized_client_key = cf_dhcpv4__dup_str(hdr->chaddr_mac);
    else
        interp->normalized_client_key = cf_dhcpv4__dup_str("");

    /* transaction_key: xid hex + chaddr_mac, or xid hex + client-id hex
     * when there is no MAC, or just xid hex when neither is available. */
    {
        char xidhex[9];
        const char *suffix = NULL;

        snprintf(xidhex, sizeof(xidhex), "%08x", hdr->xid);
        if (hdr->chaddr_mac[0] != '\0')
            suffix = hdr->chaddr_mac;
        else if (client_hex)
            suffix = client_hex;

        if (suffix) {
            size_t n = strlen(xidhex) + 1 + strlen(suffix) + 1;
            char *tk = malloc(n);
            if (tk) {
                snprintf(tk, n, "%s-%s", xidhex, suffix);
                interp->transaction_key = tk;
            } else {
                interp->transaction_key = cf_dhcpv4__dup_str(xidhex);
            }
        } else {
            interp->transaction_key = cf_dhcpv4__dup_str(xidhex);
        }
    }

    if (client_hex && client_hex != (char *)protobuf_c_empty_string)
        free(client_hex);

    /* lease_address: yiaddr for OFFER/ACK only. */
    if (decoded->message_type == CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__OFFER ||
        decoded->message_type == CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__ACK) {
        interp->lease_address = cf_dhcpv4__dup_str(hdr->yiaddr);
    } else {
        interp->lease_address = cf_dhcpv4__dup_str("");
    }

    interp->is_relayed = strcmp(hdr->giaddr, "0.0.0.0") != 0;
    interp->is_broadcast = (hdr->flags & 0x8000u) != 0;

    /* is_renewal / is_rebind: best-effort heuristic, not a wire fact --
     * RFC 2131 does not put "this REQUEST is a renewal vs. a rebind" on the
     * wire directly. A REQUEST that carries neither server-identifier (54)
     * nor requested-ip (50) is, by elimination, neither the
     * SELECTING-state REQUEST (which always has both) nor the
     * INIT-REBOOT-state REQUEST (which always has requested-ip); that
     * leaves RENEWING (client unicasts straight to its lease's server) and
     * REBINDING (client broadcasts because the original server is
     * unreachable) as the only remaining RFC 2131 states, which the
     * client's own broadcast flag choice then distinguishes. This is
     * DERIVED, not OBSERVED: a client could technically violate the RFC
     * and this heuristic would misclassify it.
     */
    interp->is_renewal = 0;
    interp->is_rebind = 0;
    if (decoded->message_type == CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__REQUEST &&
        decoded->server_identifier[0] == '\0' &&
        decoded->requested_ip_address[0] == '\0') {
        if (interp->is_broadcast)
            interp->is_rebind = 1;
        else
            interp->is_renewal = 1;
    }

    return interp;
}

/* ---- entry point ---------------------------------------------------------- */

Cloudflow__V1__DhcpV4PacketEvent *
cf_dhcpv4_parse(const uint8_t *payload, size_t len, const char **event_type)
{
    Cloudflow__V1__DhcpV4PacketEvent *ev;
    Cloudflow__V1__DhcpV4Header *hdr;
    raw_item_list_t items;
    cf_dhcpv4_concat_map_t cm;
    cf_dhcpv4_warn_list_t warnings;
    int overload_value = 0;
    const char *derived_event_type;
    size_t i;

    if (event_type)
        *event_type = NULL;

    if (!payload || len < BOOTP_FIXED_LEN)
        return NULL;

    ev = calloc(1, sizeof(*ev));
    if (!ev)
        return NULL;
    cloudflow__v1__dhcp_v4_packet_event__init(ev);

    hdr = build_header(payload, len);
    if (!hdr) {
        free(ev);
        return NULL;
    }
    ev->header = hdr;

    raw_item_list_init(&items);
    cf_dhcpv4__concat_map_init(&cm);
    cf_dhcpv4__warn_list_init(&warnings);

    if (len > BOOTP_OPTIONS_OFF && hdr->magic_cookie_present) {
        walk_options_field(payload + BOOTP_OPTIONS_OFF, len - BOOTP_OPTIONS_OFF,
                            CLOUDFLOW__V1__DHCP_V4_OPTION__SOURCE_FIELD__SOURCE_FIELD_OPTIONS,
                            &items, &cm, &warnings, &overload_value);
    }

    /* Option 52 overload (RFC 2132 9.3): 1 = file field holds options,
     * 2 = sname field holds options, 3 = both. Walked in "file then sname"
     * order (matching common reference-implementation behavior; RFC 3396
     * does not mandate an order between fields, only within one). */
    if (overload_value & 0x1) {
        walk_options_field(payload + BOOTP_FILE_OFF, BOOTP_FILE_LEN,
                            CLOUDFLOW__V1__DHCP_V4_OPTION__SOURCE_FIELD__SOURCE_FIELD_FILE,
                            &items, &cm, &warnings, NULL);
    }
    if (overload_value & 0x2) {
        walk_options_field(payload + BOOTP_SNAME_OFF, BOOTP_SNAME_LEN,
                            CLOUDFLOW__V1__DHCP_V4_OPTION__SOURCE_FIELD__SOURCE_FIELD_SNAME,
                            &items, &cm, &warnings, NULL);
    }

    /* RFC 3396: mark every occurrence of a code that appears more than
     * once (across all source fields) as a long-option fragment; decoding
     * concatenates them (see cf_dhcpv4__build_decoded / the concat map
     * built above, which already accumulated in the same order). */
    for (i = 0; i < items.count; i++) {
        size_t j;
        int dupes = 0;
        for (j = 0; j < items.count; j++) {
            if (items.items[j].code == items.items[i].code)
                dupes++;
        }
        if (dupes > 1)
            items.items[i].long_option_fragment = 1;
    }

    ev->n_raw_options = items.count;
    if (items.count > 0) {
        ev->raw_options = malloc(items.count * sizeof(*ev->raw_options));
        if (!ev->raw_options) {
            ev->n_raw_options = 0;
        }
    }
    for (i = 0; i < ev->n_raw_options; i++) {
        raw_item_t *src = &items.items[i];
        Cloudflow__V1__DhcpV4Option *opt = calloc(1, sizeof(*opt));

        if (!opt) {
            ev->n_raw_options = i;
            break;
        }
        cloudflow__v1__dhcp_v4_option__init(opt);
        opt->code = src->code;
        opt->name = cf_dhcpv4__dup_str(cf_dhcpv4_option_name(src->code));
        opt->length = (uint32_t)src->value_len;
        cf_dhcpv4__set_bytes(&opt->raw_value, src->value, src->value_len);
        opt->source_field = src->source_field;
        opt->ordinal = src->ordinal;
        opt->malformed = src->malformed;
        opt->long_option_fragment = src->long_option_fragment;

        ev->raw_options[i] = opt;
    }

    raw_item_list_free(&items);

    cf_dhcpv4__build_decoded(&cm, &ev->decoded, &warnings);
    cf_dhcpv4__concat_map_free(&cm);

    if (!ev->decoded) {
        /* Allocation failure building the decoded-options message: treat
         * the whole parse as failed rather than hand back a tree with a
         * required field missing. */
        size_t wn;
        Cloudflow__V1__ParserWarning **witems;
        cf_dhcpv4__warn_list_take(&warnings, &wn, &witems);
        if (witems) {
            for (i = 0; i < wn; i++)
                cloudflow__v1__parser_warning__free_unpacked(witems[i], NULL);
            free(witems);
        }
        cf_dhcpv4_event_free(ev);
        return NULL;
    }

    derived_event_type = event_type_for_message_type(ev->decoded->message_type);
    ev->interpretation = build_interpretation(hdr, ev->decoded, derived_event_type);

    cf_dhcpv4__set_bytes(&ev->raw_dhcp_payload, payload, len);
    ev->raw_payload_truncated = 0;

    cf_dhcpv4__warn_list_take(&warnings, &ev->n_parser_warnings, &ev->parser_warnings);

    if (event_type)
        *event_type = derived_event_type;

    return ev;
}

void cf_dhcpv4_event_free(Cloudflow__V1__DhcpV4PacketEvent *ev)
{
    if (!ev)
        return;
    cloudflow__v1__dhcp_v4_packet_event__free_unpacked(ev, NULL);
}
