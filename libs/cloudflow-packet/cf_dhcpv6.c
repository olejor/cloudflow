/* WP-07 DHCPv6 parser: fixed header (client/server transaction-id, or
 * RELAY-FORW/RELAY-REPL hop-count/link-address/peer-address), and the
 * top-level raw option wire walk. The decoded-option builder (option-by-
 * option semantic decode) lives in cf_dhcpv6_decode.c; shared helpers live
 * in cf_dhcpv6_util.c. See docs/dhcp-source.md for the
 * spec this implements, and import/network_dhcp_collector/src/main.c's
 * process_dhcpv6 for the TLV-walk shape this is lifted from (msg-type +
 * 24-bit xid, then a flat code/len/value option loop with memcpy
 * discipline) -- extended here with bounds-checked resync-on-malformed,
 * relay-message header handling, and full protobuf output.
 *
 * Never trusts lengths: every header/option field read is checked against
 * the remaining buffer before use. A malformed option marks itself
 * (DhcpV6Option.malformed = true), emits a ParserWarning with up to 16
 * bytes of raw_context, and parsing resumes at the best available point --
 * for a length overrun that point is "nothing further in this option area
 * is trustworthy", so the walk stops there (the header fields already read
 * are still reported).
 */

#include "cf_dhcpv6.h"
#include "cf_dhcpv6_internal.h"
#include "cf_dhcpv6_optnames.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cf_ipfmt.h"

/* ---- DHCPv6 fixed-header layout ------------------------------------------
 *
 * Every message starts with a 1-byte msg-type. Client/server messages
 * (SOLICIT..INFORMATION-REQUEST, LEASEQUERY*) follow it with a 3-byte
 * transaction-id (RFC 8415 section 8). RELAY-FORW/RELAY-REPL (RFC 8415
 * section 9) instead follow it with hop-count(1), link-address(16),
 * peer-address(16) -- no transaction-id of their own.
 */

#define DHCPV6_MSG_TYPE_OFF   0
#define DHCPV6_XID_OFF        1
#define DHCPV6_MIN_HEADER_LEN 4 /* msg-type + 3-byte xid, or the first byte of hop-count */

#define DHCPV6_RELAY_HOPCOUNT_OFF 1
#define DHCPV6_RELAY_LINKADDR_OFF 2
#define DHCPV6_RELAY_PEERADDR_OFF 18
#define DHCPV6_RELAY_FIXED_LEN    34 /* msg-type + hop-count + link-addr(16) + peer-addr(16) */

#define DHCPV6_MSGTYPE_RELAY_FORW 12
#define DHCPV6_MSGTYPE_RELAY_REPL 13

static int is_relay_message_type(uint8_t v)
{
    return v == DHCPV6_MSGTYPE_RELAY_FORW || v == DHCPV6_MSGTYPE_RELAY_REPL;
}

/* The proto enum's numeric values are defined to match the IANA "DHCPv6
 * Message Types" registry exactly (1..17), so a valid wire value can be
 * cast directly; anything outside that range (0, or >17) is unassigned. */
static Cloudflow__V1__DhcpV6Header__MessageType message_type_enum(uint8_t v)
{
    if (v >= 1 && v <= 17)
        return (Cloudflow__V1__DhcpV6Header__MessageType)v;
    return CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__MESSAGE_TYPE_UNSPECIFIED;
}

/* Builds the header and returns the byte offset options start at
 * (4 for client/server messages, 34 for RELAY-FORW/RELAY-REPL). `len` is
 * already known to be >= DHCPV6_MIN_HEADER_LEN by the caller. */
static Cloudflow__V1__DhcpV6Header *build_header(const uint8_t *payload, size_t len,
                                                   size_t *options_offset_out)
{
    Cloudflow__V1__DhcpV6Header *hdr = calloc(1, sizeof(*hdr));
    uint8_t msg_type_raw = payload[DHCPV6_MSG_TYPE_OFF];

    if (!hdr)
        return NULL;
    cloudflow__v1__dhcp_v6_header__init(hdr);

    hdr->message_type = message_type_enum(msg_type_raw);

    if (is_relay_message_type(msg_type_raw)) {
        uint8_t hop;

        if (cf_dhcpv6__get_u8(payload, len, DHCPV6_RELAY_HOPCOUNT_OFF, &hop))
            hdr->hop_count = hop;

        if (len >= DHCPV6_RELAY_LINKADDR_OFF + 16) {
            char buf[46];

            cf_format_ip(buf, 6, payload + DHCPV6_RELAY_LINKADDR_OFF);
            hdr->link_address = cf_dhcpv6__dup_str(buf);
        }
        if (len >= DHCPV6_RELAY_PEERADDR_OFF + 16) {
            char buf[46];

            cf_format_ip(buf, 6, payload + DHCPV6_RELAY_PEERADDR_OFF);
            hdr->peer_address = cf_dhcpv6__dup_str(buf);
        }

        *options_offset_out = DHCPV6_RELAY_FIXED_LEN;
    } else {
        uint32_t xid;

        /* Always available: len >= DHCPV6_MIN_HEADER_LEN (4) is the
         * caller's precondition, and the xid is bytes [1,4). */
        if (cf_dhcpv6__get_be24(payload, len, DHCPV6_XID_OFF, &xid))
            hdr->transaction_id = xid;

        *options_offset_out = DHCPV6_MIN_HEADER_LEN;
    }

    return hdr;
}

/* ---- top-level raw option walk --------------------------------------------
 *
 * DHCPv6 options have no pad/end sentinel (unlike DHCPv4): every option is a
 * 4-byte code/length header followed by that many bytes of value, back to
 * back until the field runs out.
 */
static void walk_options(const uint8_t *field, size_t field_len,
                          cf_dhcpv6_raw_item_list_t *list, cf_dhcpv6_warn_list_t *warnings)
{
    size_t pos = 0;
    uint32_t ordinal = 0;
    char path[40];

    while (pos < field_len) {
        if (pos + 4 > field_len) {
            /* Truncated before (or partway through) the 4-byte code/length
             * header. Recover as much of the code as is present. */
            uint16_t code = 0;

            if (pos + 2 <= field_len)
                code = (uint16_t)(((uint16_t)field[pos] << 8) | field[pos + 1]);

            snprintf(path, sizeof(path), "raw_options[%zu]", list->count);
            cf_dhcpv6__warn(warnings, "opt_missing_header",
                             "option present but truncated before its 4-byte code/length header",
                             path, field + pos, field_len - pos);
            cf_dhcpv6__raw_item_list_append(list, code, ordinal, field + pos,
                                             field_len - pos, 1);
            break; /* nothing reliable remains in this field */
        }

        {
            uint16_t code = (uint16_t)(((uint16_t)field[pos] << 8) | field[pos + 1]);
            uint16_t declared_len = (uint16_t)(((uint16_t)field[pos + 2] << 8) | field[pos + 3]);
            size_t avail = field_len - (pos + 4);
            size_t use_len = declared_len;
            int malformed = 0;
            const uint8_t *value_ptr = field + pos + 4;

            if (declared_len > avail) {
                use_len = avail;
                malformed = 1;
            }

            snprintf(path, sizeof(path), "raw_options[%zu]", list->count);
            cf_dhcpv6__raw_item_list_append(list, code, ordinal, value_ptr, use_len, malformed);

            if (malformed) {
                cf_dhcpv6__warn(warnings, "opt_len_overrun",
                                 "option length exceeds remaining bytes in this field",
                                 path, value_ptr, use_len);
            }

            ordinal++;

            if (malformed)
                break; /* best resync: rest of this field is untrustworthy */

            pos += 4 + use_len;
        }
    }
}

/* ---- interpretation / event type ------------------------------------------ */

static const char *event_type_for_message_type(Cloudflow__V1__DhcpV6Header__MessageType mt)
{
    switch (mt) {
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__SOLICIT:
        return "dhcpv6.solicit.observed";
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__ADVERTISE:
        return "dhcpv6.advertise.observed";
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__REQUEST:
        return "dhcpv6.request.observed";
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__CONFIRM:
        return "dhcpv6.confirm.observed";
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__RENEW:
        return "dhcpv6.renew.observed";
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__REBIND:
        return "dhcpv6.rebind.observed";
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__REPLY:
        return "dhcpv6.reply.observed";
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__RELEASE:
        return "dhcpv6.release.observed";
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__DECLINE:
        return "dhcpv6.decline.observed";
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__RECONFIGURE:
        return "dhcpv6.reconfigure.observed";
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__INFORMATION_REQUEST:
        return "dhcpv6.information-request.observed";
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__RELAY_FORW:
        return "dhcpv6.relay-forw.observed";
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__RELAY_REPL:
        return "dhcpv6.relay-repl.observed";
    /* LEASEQUERY/LEASEQUERY_REPLY/LEASEQUERY_DONE/LEASEQUERY_DATA are valid
     * wire message types but are not (yet) in the event-type vocabulary
     * (docs/dhcp-source.md's WP-07 section only lists the
     * above plus the two relay types) -- fall through to the generic type,
     * same as MESSAGE_TYPE_UNSPECIFIED / any unassigned wire value. */
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__LEASEQUERY:
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__LEASEQUERY_REPLY:
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__LEASEQUERY_DONE:
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__LEASEQUERY_DATA:
    case CLOUDFLOW__V1__DHCP_V6_HEADER__MESSAGE_TYPE__MESSAGE_TYPE_UNSPECIFIED:
    default:
        return "dhcpv6.packet.observed";
    }
}

/* ---- entry point ---------------------------------------------------------- */

Cloudflow__V1__DhcpV6PacketEvent *
cf_dhcpv6_parse(const uint8_t *payload, size_t len, const char **event_type)
{
    Cloudflow__V1__DhcpV6PacketEvent *ev;
    Cloudflow__V1__DhcpV6Header *hdr;
    cf_dhcpv6_raw_item_list_t items;
    cf_dhcpv6_warn_list_t warnings;
    size_t options_offset;
    const char *derived_event_type;
    size_t i;

    if (event_type)
        *event_type = NULL;

    if (!payload || len < DHCPV6_MIN_HEADER_LEN)
        return NULL;

    ev = calloc(1, sizeof(*ev));
    if (!ev)
        return NULL;
    cloudflow__v1__dhcp_v6_packet_event__init(ev);

    hdr = build_header(payload, len, &options_offset);
    if (!hdr) {
        free(ev);
        return NULL;
    }
    ev->header = hdr;

    cf_dhcpv6__raw_item_list_init(&items);
    cf_dhcpv6__warn_list_init(&warnings);

    if (len > options_offset)
        walk_options(payload + options_offset, len - options_offset, &items, &warnings);

    cf_dhcpv6__build_decoded(items.items, items.count, &ev->decoded, &warnings);

    if (!ev->decoded) {
        /* Allocation failure building the decoded-options message: treat
         * the whole parse as failed rather than hand back a tree with a
         * required field missing. */
        size_t wn;
        Cloudflow__V1__ParserWarning **witems;

        cf_dhcpv6__raw_item_list_free(&items);
        cf_dhcpv6__warn_list_take(&warnings, &wn, &witems);
        if (witems) {
            for (i = 0; i < wn; i++)
                cloudflow__v1__parser_warning__free_unpacked(witems[i], NULL);
            free(witems);
        }
        cf_dhcpv6_event_free(ev);
        return NULL;
    }

    ev->n_raw_options = items.count;
    if (items.count > 0) {
        ev->raw_options = malloc(items.count * sizeof(*ev->raw_options));
        if (!ev->raw_options)
            ev->n_raw_options = 0;
    }
    for (i = 0; i < ev->n_raw_options; i++) {
        cf_dhcpv6_raw_item_t *src = &items.items[i];
        Cloudflow__V1__DhcpV6Option *opt = calloc(1, sizeof(*opt));

        if (!opt) {
            ev->n_raw_options = i;
            break;
        }
        cloudflow__v1__dhcp_v6_option__init(opt);
        opt->code = src->code;
        opt->name = cf_dhcpv6__dup_str(cf_dhcpv6_option_name(src->code));
        opt->length = (uint32_t)src->value_len;
        cf_dhcpv6__set_bytes(&opt->raw_value, src->value, src->value_len);
        opt->ordinal = src->ordinal;
        opt->malformed = src->malformed;

        ev->raw_options[i] = opt;
    }

    cf_dhcpv6__raw_item_list_free(&items);

    derived_event_type = event_type_for_message_type(hdr->message_type);

    cf_dhcpv6__set_bytes(&ev->raw_dhcp_payload, payload, len);
    ev->raw_payload_truncated = 0;

    cf_dhcpv6__warn_list_take(&warnings, &ev->n_parser_warnings, &ev->parser_warnings);

    if (event_type)
        *event_type = derived_event_type;

    return ev;
}

void cf_dhcpv6_event_free(Cloudflow__V1__DhcpV6PacketEvent *ev)
{
    if (!ev)
        return;
    cloudflow__v1__dhcp_v6_packet_event__free_unpacked(ev, NULL);
}
