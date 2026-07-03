/* WP-07 DHCPv6 parser: DhcpV6DecodedOptions builder. Consumes the top-level
 * raw option list built by cf_dhcpv6.c's option walk and produces the
 * best-effort semantic decode of the options named in dhcp.proto's
 * DhcpV6DecodedOptions: client DUID (1), server DUID (2), IA_NA (3) / IA_TA
 * (4) walked one level deep to collect IAADDR (5) addresses into
 * assigned_addresses, ORO (6) codes, vendor class (16), and vendor-specific
 * information (17) with its enterprise number and suboption walk. Per the
 * WP-07 spec, nested options are not recursed into except for this IA ->
 * IAADDR walk (one level deep) and the vendor-opts suboption walk -- both
 * "as required for decoded fields" cases the spec calls out.
 *
 * Every fixed-length field is bounds-checked against the actual option
 * length; a too-short value is left at its proto3 default and reported via
 * a ParserWarning instead of reading past the end of the option data. When
 * an option code repeats (e.g. two IA_NA options, or two ORO options),
 * singleton fields (client/server DUID, vendor class, vendor options) take
 * the first occurrence; list-valued fields (assigned_addresses, the ORO
 * code list) aggregate across every occurrence, in wire order.
 */

#include "cf_dhcpv6_internal.h"

#include <stdlib.h>
#include <string.h>

#define OPT_CLIENTID     1
#define OPT_SERVERID     2
#define OPT_IA_NA        3
#define OPT_IA_TA        4
#define OPT_IAADDR       5
#define OPT_ORO          6
#define OPT_VENDOR_CLASS 16
#define OPT_VENDOR_OPTS  17

/* ---- IA_NA / IA_TA -> IAADDR one-level-deep walk -------------------------
 *
 * IA_NA: IAID(4) T1(4) T2(4) then a sequence of options. IA_TA: IAID(4)
 * then a sequence of options (no T1/T2). Only IAADDR (5) suboptions are of
 * interest here; any other suboption code inside an IA is skipped (its
 * bytes are still consumed to keep walking forward).
 */
static void collect_addresses_from_ia(const uint8_t *data, size_t len, int is_ia_na,
                                       char ***addrs, size_t *n_addrs, size_t *cap_addrs,
                                       cf_dhcpv6_warn_list_t *warnings)
{
    size_t hdr_len = is_ia_na ? 12 : 4;
    size_t pos;

    if (len < hdr_len) {
        cf_dhcpv6__warn(warnings, "ia_len_short",
                         is_ia_na ? "IA_NA option shorter than its 12-byte IAID/T1/T2 header"
                                  : "IA_TA option shorter than its 4-byte IAID header",
                         "decoded.assigned_addresses", data, len);
        return;
    }

    pos = hdr_len;
    while (pos + 4 <= len) {
        uint16_t code = (uint16_t)(((uint16_t)data[pos] << 8) | data[pos + 1]);
        uint16_t declared_len = (uint16_t)(((uint16_t)data[pos + 2] << 8) | data[pos + 3]);
        size_t avail = len - (pos + 4);
        size_t use_len = declared_len;
        int malformed = 0;

        if (declared_len > avail) {
            use_len = avail;
            malformed = 1;
        }

        if (code == OPT_IAADDR) {
            if (use_len >= 16) {
                char *addr = cf_dhcpv6__format_ipv6(data + pos + 4);

                if (!addr) {
                    /* allocation failure: drop silently, nothing more we
                     * can do without a warnings-list entry for OOM. */
                } else if (*n_addrs == *cap_addrs) {
                    size_t ncap = *cap_addrs == 0 ? 4 : *cap_addrs * 2;
                    char **ni = realloc(*addrs, ncap * sizeof(*ni));

                    if (ni) {
                        *addrs = ni;
                        *cap_addrs = ncap;
                        (*addrs)[(*n_addrs)++] = addr;
                    } else {
                        if (addr != (char *)protobuf_c_empty_string)
                            free(addr);
                    }
                } else {
                    (*addrs)[(*n_addrs)++] = addr;
                }
            } else {
                cf_dhcpv6__warn(warnings, "iaaddr_len_short",
                                 "IAADDR suboption shorter than its 24-byte address/lifetimes",
                                 "decoded.assigned_addresses", data + pos, len - pos);
            }
        }

        if (malformed) {
            cf_dhcpv6__warn(warnings, "opt_len_overrun",
                             "IA suboption length exceeds remaining IA option bytes",
                             "decoded.assigned_addresses", data + pos, len - pos);
            break;
        }
        pos += 4 + use_len;
    }
}

/* ---- option 16 vendor class -----------------------------------------------
 *
 * enterprise-number(4) then one or more <opaque-len(2), opaque-data> vendor
 * class data chunks (RFC 8415 21.16). vendor_class in the proto is a single
 * string, so only the first chunk is decoded (the overwhelming common case
 * in practice is exactly one chunk).
 */
static void decode_vendor_class(const uint8_t *data, size_t len,
                                 Cloudflow__V1__DhcpV6DecodedOptions *d,
                                 cf_dhcpv6_warn_list_t *warnings)
{
    size_t pos;

    if (len < 4) {
        cf_dhcpv6__warn(warnings, "opt_len_short",
                         "option 16 (vendor class) shorter than its 4-byte enterprise number",
                         "decoded.vendor_class", data, len);
        return;
    }

    pos = 4;
    if (pos + 2 > len) {
        if (pos < len) {
            cf_dhcpv6__warn(warnings, "opt_len_short",
                             "vendor-class-data present but truncated before its length",
                             "decoded.vendor_class", data + pos, len - pos);
        }
        return;
    }

    {
        uint16_t chunk_len = (uint16_t)(((uint16_t)data[pos] << 8) | data[pos + 1]);
        size_t avail = len - (pos + 2);
        size_t use_len = chunk_len;

        if (chunk_len > avail) {
            use_len = avail;
            cf_dhcpv6__warn(warnings, "opt_len_overrun",
                             "vendor-class-data length exceeds remaining option bytes",
                             "decoded.vendor_class", data + pos + 2, avail);
        }
        if (use_len > 0) {
            if (cf_dhcpv6__is_printable(data + pos + 2, use_len))
                d->vendor_class = cf_dhcpv6__dup_strn(data + pos + 2, use_len);
            else
                d->vendor_class = cf_dhcpv6__hex_encode(data + pos + 2, use_len);
        }
    }
}

/* ---- option 17 vendor-specific information --------------------------------
 *
 * enterprise-number(4) then a sequence of <opt-code(2), opt-len(2),
 * opt-data> suboptions (RFC 8415 21.17).
 */
static void decode_vendor_options(const uint8_t *data, size_t len,
                                   Cloudflow__V1__DhcpV6DecodedOptions *d,
                                   cf_dhcpv6_warn_list_t *warnings)
{
    Cloudflow__V1__DhcpV6VendorOptions *vo = calloc(1, sizeof(*vo));
    size_t pos;
    Cloudflow__V1__DhcpV6VendorSuboption **arr = NULL;
    size_t n = 0, cap = 0;

    if (!vo)
        return;
    cloudflow__v1__dhcp_v6_vendor_options__init(vo);
    cf_dhcpv6__set_bytes(&vo->raw_value, data, len);
    d->vendor_options = vo;

    if (len < 4) {
        cf_dhcpv6__warn(warnings, "opt_len_short",
                         "option 17 (vendor-specific info) shorter than its 4-byte enterprise number",
                         "decoded.vendor_options", data, len);
        return;
    }
    vo->enterprise_number = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
                             ((uint32_t)data[2] << 8) | (uint32_t)data[3];

    pos = 4;
    while (pos + 4 <= len) {
        uint16_t code = (uint16_t)(((uint16_t)data[pos] << 8) | data[pos + 1]);
        uint16_t declared_len = (uint16_t)(((uint16_t)data[pos + 2] << 8) | data[pos + 3]);
        size_t avail = len - (pos + 4);
        size_t use_len = declared_len;
        int malformed = 0;
        Cloudflow__V1__DhcpV6VendorSuboption *so;

        if (declared_len > avail) {
            use_len = avail;
            malformed = 1;
        }

        so = calloc(1, sizeof(*so));
        if (!so)
            break;
        cloudflow__v1__dhcp_v6_vendor_suboption__init(so);
        so->code = code;
        so->length = (uint32_t)use_len;
        cf_dhcpv6__set_bytes(&so->raw_value, data + pos + 4, use_len);
        if (cf_dhcpv6__is_printable(data + pos + 4, use_len))
            so->decoded_value = cf_dhcpv6__dup_strn(data + pos + 4, use_len);
        else
            so->decoded_value = cf_dhcpv6__hex_encode(data + pos + 4, use_len);

        if (malformed) {
            cf_dhcpv6__warn(warnings, "opt_len_overrun",
                             "vendor suboption length exceeds remaining option bytes",
                             "decoded.vendor_options.suboptions", data + pos + 4, use_len);
        }

        if (n == cap) {
            size_t ncap = cap == 0 ? 4 : cap * 2;
            Cloudflow__V1__DhcpV6VendorSuboption **ni = realloc(arr, ncap * sizeof(*ni));

            if (!ni) {
                cloudflow__v1__dhcp_v6_vendor_suboption__free_unpacked(so, NULL);
                break;
            }
            arr = ni;
            cap = ncap;
        }
        arr[n++] = so;

        if (malformed)
            break;
        pos += 4 + use_len;
    }

    vo->n_suboptions = n;
    vo->suboptions = arr;
}

/* ---- option 6 ORO (option request option) list append --------------------- */

static void append_u32(uint32_t **arr, size_t *n, size_t *cap, uint32_t v)
{
    if (*n == *cap) {
        size_t ncap = *cap == 0 ? 8 : *cap * 2;
        uint32_t *ni = realloc(*arr, ncap * sizeof(*ni));

        if (!ni)
            return;
        *arr = ni;
        *cap = ncap;
    }
    (*arr)[(*n)++] = v;
}

/* ---- top-level entry point ------------------------------------------------ */

void cf_dhcpv6__build_decoded(const cf_dhcpv6_raw_item_t *items, size_t n_items,
                               Cloudflow__V1__DhcpV6DecodedOptions **out,
                               cf_dhcpv6_warn_list_t *warnings)
{
    Cloudflow__V1__DhcpV6DecodedOptions *d = calloc(1, sizeof(*d));
    size_t i;
    char **addrs = NULL;
    size_t n_addrs = 0, cap_addrs = 0;
    uint32_t *oro = NULL;
    size_t n_oro = 0, cap_oro = 0;
    int have_client_duid = 0, have_server_duid = 0;
    int have_vendor_class = 0, have_vendor_opts = 0;

    if (!d) {
        *out = NULL;
        return;
    }
    cloudflow__v1__dhcp_v6_decoded_options__init(d);

    for (i = 0; i < n_items; i++) {
        const cf_dhcpv6_raw_item_t *it = &items[i];

        switch (it->code) {
        case OPT_CLIENTID:
            if (!have_client_duid) {
                cf_dhcpv6__set_bytes(&d->client_duid, it->value, it->value_len);
                have_client_duid = 1;
            }
            break;
        case OPT_SERVERID:
            if (!have_server_duid) {
                cf_dhcpv6__set_bytes(&d->server_duid, it->value, it->value_len);
                have_server_duid = 1;
            }
            break;
        case OPT_IA_NA:
            collect_addresses_from_ia(it->value, it->value_len, 1, &addrs, &n_addrs,
                                       &cap_addrs, warnings);
            break;
        case OPT_IA_TA:
            collect_addresses_from_ia(it->value, it->value_len, 0, &addrs, &n_addrs,
                                       &cap_addrs, warnings);
            break;
        case OPT_ORO: {
            size_t n2 = it->value_len / 2;
            size_t j;

            if (it->value_len % 2 != 0) {
                cf_dhcpv6__warn(warnings, "opt_len_invalid",
                                 "option request option length is not a multiple of 2 bytes",
                                 "decoded.option_request_option_codes", it->value,
                                 it->value_len);
            }
            for (j = 0; j < n2; j++) {
                uint16_t code16 =
                    (uint16_t)(((uint16_t)it->value[2 * j] << 8) | it->value[2 * j + 1]);
                append_u32(&oro, &n_oro, &cap_oro, code16);
            }
            break;
        }
        case OPT_VENDOR_CLASS:
            if (!have_vendor_class) {
                decode_vendor_class(it->value, it->value_len, d, warnings);
                have_vendor_class = 1;
            }
            break;
        case OPT_VENDOR_OPTS:
            if (!have_vendor_opts) {
                decode_vendor_options(it->value, it->value_len, d, warnings);
                have_vendor_opts = 1;
            }
            break;
        default:
            break;
        }
    }

    d->assigned_addresses = addrs;
    d->n_assigned_addresses = n_addrs;
    d->option_request_option_codes = oro;
    d->n_option_request_option_codes = n_oro;

    *out = d;
}
