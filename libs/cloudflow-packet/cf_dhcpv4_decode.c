/* WP-06 DHCPv4 parser: DhcpV4DecodedOptions builder. Consumes the RFC 3396
 * "concatenate same-code fragments before interpreting" map built by
 * cf_dhcpv4.c's option walk and produces the best-effort semantic decode of
 * every option in the DhcpV4DecodedOptions message (dhcp.proto). Every
 * fixed-length field is bounds-checked against the actual concatenated
 * length; a too-short value is left at its proto3 default and reported via
 * a ParserWarning instead of reading past the end of the option data.
 */

#include "cf_dhcpv4_internal.h"
#include "cf_dhcpv4_optnames.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cf_ipfmt.h"

/* ---- small scalar decoders ------------------------------------------------
 *
 * Each returns 1 (and fills *out / returns an owned string) on success, or
 * 0 (leaving the field at its proto3 default) when there are not enough
 * bytes, after recording a ParserWarning. Extra trailing bytes beyond the
 * required length are tolerated silently (seen in the wild from padded
 * clients) rather than flagged malformed.
 */

static char *decode_ipv4_scalar(const uint8_t *data, size_t len,
                                 const char *field_path, cf_dhcpv4_warn_list_t *warnings)
{
    if (len < 4) {
        cf_dhcpv4__warn(warnings, "opt_len_short", "expected a 4-byte IPv4 address",
                         field_path, data, len);
        return NULL;
    }
    return cf_dhcpv4__format_ipv4(data);
}

static void decode_ipv4_list(const uint8_t *data, size_t len, char ***out_arr,
                              size_t *out_n, const char *field_path,
                              cf_dhcpv4_warn_list_t *warnings)
{
    size_t n = len / 4;
    size_t rem = len % 4;
    size_t i;
    char **arr;

    if (rem != 0) {
        cf_dhcpv4__warn(warnings, "opt_len_invalid",
                         "option length is not a multiple of 4 bytes", field_path,
                         data + (len - rem), rem);
    }
    *out_arr = NULL;
    *out_n = 0;
    if (n == 0)
        return;

    arr = malloc(n * sizeof(*arr));
    if (!arr)
        return;
    for (i = 0; i < n; i++)
        arr[i] = cf_dhcpv4__format_ipv4(data + i * 4);
    *out_arr = arr;
    *out_n = n;
}

static int decode_u32(const uint8_t *data, size_t len, uint32_t *out,
                       const char *field_path, cf_dhcpv4_warn_list_t *warnings)
{
    if (len < 4) {
        cf_dhcpv4__warn(warnings, "opt_len_short", "expected a 4-byte integer",
                         field_path, data, len);
        return 0;
    }
    *out = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) | (uint32_t)data[3];
    return 1;
}

static int decode_u16_as_u32(const uint8_t *data, size_t len, uint32_t *out,
                              const char *field_path, cf_dhcpv4_warn_list_t *warnings)
{
    if (len < 2) {
        cf_dhcpv4__warn(warnings, "opt_len_short", "expected a 2-byte integer",
                         field_path, data, len);
        return 0;
    }
    *out = ((uint32_t)data[0] << 8) | (uint32_t)data[1];
    return 1;
}

/* ---- option 53 message type ---------------------------------------------- */

static const char *message_type_name(uint8_t v)
{
    switch (v) {
    case 1:  return "DISCOVER";
    case 2:  return "OFFER";
    case 3:  return "REQUEST";
    case 4:  return "DECLINE";
    case 5:  return "ACK";
    case 6:  return "NAK";
    case 7:  return "RELEASE";
    case 8:  return "INFORM";
    case 9:  return "FORCERENEW";
    case 10: return "LEASEQUERY";
    case 11: return "LEASEUNASSIGNED";
    case 12: return "LEASEUNKNOWN";
    case 13: return "LEASEACTIVE";
    default: return "";
    }
}

static Cloudflow__V1__DhcpV4DecodedOptions__MessageType message_type_enum(uint8_t v)
{
    switch (v) {
    case 1:  return CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__DISCOVER;
    case 2:  return CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__OFFER;
    case 3:  return CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__REQUEST;
    case 4:  return CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__DECLINE;
    case 5:  return CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__ACK;
    case 6:  return CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__NAK;
    case 7:  return CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__RELEASE;
    case 8:  return CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__INFORM;
    case 9:  return CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__FORCERENEW;
    case 10: return CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__LEASEQUERY;
    case 11: return CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__LEASEUNASSIGNED;
    case 12: return CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__LEASEUNKNOWN;
    case 13: return CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__LEASEACTIVE;
    default: return CLOUDFLOW__V1__DHCP_V4_DECODED_OPTIONS__MESSAGE_TYPE__MESSAGE_TYPE_UNSPECIFIED;
    }
}

/* ---- option 61 client identifier ------------------------------------------
 *
 * RFC 2132 leaves the identifier opaque, but two conventions cover the vast
 * majority of real traffic: a leading type byte of 0 with a printable
 * string after it (common for IAID/DUID-derived or vendor-chosen text
 * identifiers), and a leading type byte of 1 (ARP/Ethernet) followed by a
 * 6-byte MAC, per RFC 2132 section 9.14's "type 1" hint. Anything else is
 * still preserved in client_identifier_raw, just without a text rendering.
 */
static void decode_client_id(const uint8_t *data, size_t len,
                              Cloudflow__V1__DhcpV4DecodedOptions *d)
{
    cf_dhcpv4__set_bytes(&d->client_identifier_raw, data, len);

    if (len == 0)
        return;

    if (data[0] == 0 && len > 1 && cf_dhcpv4__is_printable(data + 1, len - 1)) {
        d->client_identifier_text = cf_dhcpv4__dup_strn(data + 1, len - 1);
    } else if (data[0] == 1 && len == 7) {
        char macbuf[18];
        cf_format_mac(macbuf, data + 1);
        d->client_identifier_text = cf_dhcpv4__dup_str(macbuf);
    }
}

/* ---- option 119 domain search / option 81 FQDN domain name (E bit) ------
 *
 * Decodes zero or more RFC 1035 wire-format domain names, back to back,
 * from `data[0..len)`, following compression pointers -- but a pointer's
 * target must resolve to an offset within [0, len) of *this same buffer*;
 * it can never reach outside the concatenated option data (there is no
 * "full packet" here to point into, unlike a real DNS message).
 */
static void decode_domain_name_list(const uint8_t *data, size_t len, char ***out_names,
                                     size_t *out_n, cf_dhcpv4_warn_list_t *warnings,
                                     const char *field_path_prefix)
{
    size_t pos = 0;
    char **names = NULL;
    size_t n = 0, cap = 0;

    while (pos < len) {
        size_t cursor = pos;
        char *name = NULL;
        size_t name_len = 0;
        int jumps = 0;
        int had_pointer = 0;
        int error = 0;
        size_t advance_pos = pos;

        if (data[pos] == 0) { /* stray root label between names */
            pos++;
            continue;
        }

        for (;;) {
            uint8_t b;

            if (cursor >= len) {
                error = 1;
                break;
            }
            b = data[cursor];

            if (b == 0) {
                if (!had_pointer)
                    advance_pos = cursor + 1;
                break;
            }
            if ((b & 0xC0) == 0xC0) {
                size_t target;

                if (cursor + 1 >= len) {
                    error = 1;
                    break;
                }
                target = ((size_t)(b & 0x3F) << 8) | data[cursor + 1];
                if (!had_pointer)
                    advance_pos = cursor + 2;
                had_pointer = 1;
                jumps++;
                if (jumps > 64 || target >= len) {
                    error = 1;
                    break;
                }
                cursor = target;
                continue;
            }
            if ((b & 0xC0) != 0) { /* reserved label type */
                error = 1;
                break;
            }
            if (cursor + 1 + b > len) {
                error = 1;
                break;
            }
            {
                size_t add = b + (name_len > 0 ? 1 : 0);
                char *grown = realloc(name, name_len + add + 1);
                if (!grown) {
                    error = 1;
                    break;
                }
                name = grown;
                if (name_len > 0)
                    name[name_len++] = '.';
                memcpy(name + name_len, data + cursor + 1, b);
                name_len += b;
                name[name_len] = '\0';
            }
            cursor += 1 + b;
        }

        if (error) {
            char path[64];
            snprintf(path, sizeof(path), "%s[%zu]", field_path_prefix, n);
            cf_dhcpv4__warn(warnings, "domain_name_bad_encoding",
                             "domain name has an invalid/out-of-range compression "
                             "pointer or a truncated label",
                             path, data + pos, len - pos);
            free(name);
            break; /* can't reliably locate the next name */
        }

        if (name && name_len > 0) {
            if (n == cap) {
                size_t ncap = cap == 0 ? 4 : cap * 2;
                char **ni = realloc(names, ncap * sizeof(*ni));
                if (!ni) {
                    free(name);
                    break;
                }
                names = ni;
                cap = ncap;
            }
            names[n++] = name;
        } else {
            free(name);
        }

        if (advance_pos <= pos) /* safety: guarantee forward progress */
            break;
        pos = advance_pos;
    }

    *out_names = names;
    *out_n = n;
}

/* ---- options 121 / 249 classless static routes ---------------------------
 *
 * Each entry: 1 byte prefix length (0-32), ceil(prefix/8) significant
 * destination octets (zero-padded to 4 for display), 4 bytes of router.
 */
static void decode_classless_routes(const uint8_t *data, size_t len,
                                     Cloudflow__V1__DhcpV4ClasslessStaticRoute ***out_arr,
                                     size_t *out_n, cf_dhcpv4_warn_list_t *warnings,
                                     const char *field_path_prefix)
{
    size_t pos = 0;
    Cloudflow__V1__DhcpV4ClasslessStaticRoute **arr = NULL;
    size_t n = 0, cap = 0;

    while (pos < len) {
        uint8_t prefix_len = data[pos];
        size_t dest_bytes = ((size_t)prefix_len + 7) / 8;
        char path[64];

        if (prefix_len > 32) {
            snprintf(path, sizeof(path), "%s[%zu]", field_path_prefix, n);
            cf_dhcpv4__warn(warnings, "csr_bad_prefix_length",
                             "classless static route prefix length > 32", path,
                             data + pos, len - pos);
            break;
        }
        if (pos + 1 + dest_bytes + 4 > len) {
            snprintf(path, sizeof(path), "%s[%zu]", field_path_prefix, n);
            cf_dhcpv4__warn(warnings, "csr_len_overrun",
                             "classless static route entry exceeds remaining option bytes",
                             path, data + pos, len - pos);
            break;
        }

        {
            uint8_t dest4[4] = {0, 0, 0, 0};
            uint8_t router4[4];
            Cloudflow__V1__DhcpV4ClasslessStaticRoute *r = calloc(1, sizeof(*r));

            if (!r)
                break;
            cloudflow__v1__dhcp_v4_classless_static_route__init(r);

            memcpy(dest4, data + pos + 1, dest_bytes);
            memcpy(router4, data + pos + 1 + dest_bytes, 4);

            r->destination_prefix_length = prefix_len;
            r->destination = cf_dhcpv4__format_ipv4(dest4);
            r->router = cf_dhcpv4__format_ipv4(router4);
            cf_dhcpv4__set_bytes(&r->raw_value, data + pos, 1 + dest_bytes + 4);

            if (n == cap) {
                size_t ncap = cap == 0 ? 4 : cap * 2;
                Cloudflow__V1__DhcpV4ClasslessStaticRoute **ni =
                    realloc(arr, ncap * sizeof(*ni));
                if (!ni) {
                    cloudflow__v1__dhcp_v4_classless_static_route__free_unpacked(r, NULL);
                    break;
                }
                arr = ni;
                cap = ncap;
            }
            arr[n++] = r;

            pos += 1 + dest_bytes + 4;
        }
    }

    *out_arr = arr;
    *out_n = n;
}

/* ---- option 43 vendor-specific information -------------------------------
 *
 * Option 43's payload format is entirely vendor-defined. code/len/value TLV
 * (the same shape as option 82) is a common, but not universal, convention.
 * Per the WP-06 spec ("keyed off recognizable option 60"), the TLV walk is
 * only attempted when option 60 (vendor class identifier) was present --
 * that is the closest generically-available signal that this option 43 is
 * from a vendor whose suboption format is worth guessing at. raw_value is
 * always populated regardless.
 */
static void decode_vendor_specific(const uint8_t *data, size_t len,
                                    const char *vendor_class_id,
                                    Cloudflow__V1__DhcpV4DecodedOptions *d)
{
    Cloudflow__V1__DhcpV4VendorSpecificInformation *vsi = calloc(1, sizeof(*vsi));
    cf_dhcpv4_warn_list_t local;

    if (!vsi)
        return;
    cloudflow__v1__dhcp_v4_vendor_specific_information__init(vsi);
    cf_dhcpv4__set_bytes(&vsi->raw_value, data, len);
    cf_dhcpv4__warn_list_init(&local);

    if (vendor_class_id && vendor_class_id[0] != '\0') {
        size_t pos = 0;
        int ok = 1;
        Cloudflow__V1__DhcpV4VendorSuboption **arr = NULL;
        size_t n = 0, cap = 0;

        vsi->vendor_class_identifier = cf_dhcpv4__dup_str(vendor_class_id);
        vsi->decode_attempted = 1;

        while (pos < len) {
            uint8_t code, sl;
            Cloudflow__V1__DhcpV4VendorSuboption *so;

            if (pos + 2 > len) {
                cf_dhcpv4__warn(&local, "vendor_subopt_truncated",
                                 "vendor suboption truncated before its length byte",
                                 "decoded.vendor_specific_information.suboptions",
                                 data + pos, len - pos);
                ok = 0;
                break;
            }
            code = data[pos];
            sl = data[pos + 1];
            if (pos + 2 + sl > len) {
                cf_dhcpv4__warn(&local, "vendor_subopt_len_overrun",
                                 "vendor suboption length exceeds remaining bytes",
                                 "decoded.vendor_specific_information.suboptions",
                                 data + pos, len - pos);
                ok = 0;
                break;
            }

            so = calloc(1, sizeof(*so));
            if (!so) {
                ok = 0;
                break;
            }
            cloudflow__v1__dhcp_v4_vendor_suboption__init(so);
            so->code = code;
            so->length = sl;
            cf_dhcpv4__set_bytes(&so->raw_value, data + pos + 2, sl);
            if (cf_dhcpv4__is_printable(data + pos + 2, sl))
                so->decoded_value = cf_dhcpv4__dup_strn(data + pos + 2, sl);
            else
                so->decoded_value = cf_dhcpv4__hex_encode(data + pos + 2, sl);

            if (n == cap) {
                size_t ncap = cap == 0 ? 4 : cap * 2;
                Cloudflow__V1__DhcpV4VendorSuboption **ni = realloc(arr, ncap * sizeof(*ni));
                if (!ni) {
                    cloudflow__v1__dhcp_v4_vendor_suboption__free_unpacked(so, NULL);
                    ok = 0;
                    break;
                }
                arr = ni;
                cap = ncap;
            }
            arr[n++] = so;
            pos += 2 + sl;
        }

        vsi->n_suboptions = n;
        vsi->suboptions = arr;
        vsi->decode_success = ok;
    } else {
        vsi->decode_attempted = 0;
        vsi->decode_success = 0;
    }

    cf_dhcpv4__warn_list_take(&local, &vsi->n_parser_warnings, &vsi->parser_warnings);
    d->vendor_specific_information = vsi;
}

/* ---- option 82 relay agent information ------------------------------------ */

static const char *relay_suboption_name(uint32_t code)
{
    switch (code) {
    case 1: return "Agent Circuit ID";
    case 2: return "Agent Remote ID";
    case 5: return "RSVP Reservation";
    case 6: return "Subscriber ID";
    case 9: return "Vendor-Specific Relay Suboption";
    case 11: return "Relay Agent Identifier";
    case 12: return "Relay Agent Source Link Selection";
    default: return "";
    }
}

static void decode_relay_agent_info(const uint8_t *data, size_t len,
                                     Cloudflow__V1__DhcpV4DecodedOptions *d,
                                     cf_dhcpv4_warn_list_t *warnings)
{
    Cloudflow__V1__DhcpV4RelayAgentInformation *rai = calloc(1, sizeof(*rai));
    size_t pos = 0;
    Cloudflow__V1__DhcpV4RelayAgentSuboption **arr = NULL;
    size_t n = 0, cap = 0;

    if (!rai)
        return;
    cloudflow__v1__dhcp_v4_relay_agent_information__init(rai);
    cf_dhcpv4__set_bytes(&rai->raw_value, data, len);

    while (pos < len) {
        uint8_t code, sl;
        size_t use_len;
        int malformed = 0;
        Cloudflow__V1__DhcpV4RelayAgentSuboption *so;
        char path[72];

        if (pos + 2 > len) {
            snprintf(path, sizeof(path),
                     "decoded.relay_agent_information.suboptions[%zu]", n);
            cf_dhcpv4__warn(warnings, "relay_subopt_truncated",
                             "relay agent suboption truncated before its length byte",
                             path, data + pos, len - pos);

            so = calloc(1, sizeof(*so));
            if (so) {
                cloudflow__v1__dhcp_v4_relay_agent_suboption__init(so);
                so->code = data[pos];
                so->name = cf_dhcpv4__dup_str(relay_suboption_name(so->code));
                so->malformed = 1;
                if (n == cap) {
                    size_t ncap = cap == 0 ? 4 : cap * 2;
                    Cloudflow__V1__DhcpV4RelayAgentSuboption **ni =
                        realloc(arr, ncap * sizeof(*ni));
                    if (!ni) {
                        cloudflow__v1__dhcp_v4_relay_agent_suboption__free_unpacked(so, NULL);
                        so = NULL;
                    } else {
                        arr = ni;
                        cap = ncap;
                    }
                }
                if (so)
                    arr[n++] = so;
            }
            break;
        }

        code = data[pos];
        sl = data[pos + 1];
        use_len = sl;
        if (pos + 2 + sl > len) {
            use_len = len - (pos + 2);
            malformed = 1;
        }

        so = calloc(1, sizeof(*so));
        if (!so)
            break;
        cloudflow__v1__dhcp_v4_relay_agent_suboption__init(so);
        so->code = code;
        so->name = cf_dhcpv4__dup_str(relay_suboption_name(code));
        so->length = (uint32_t)use_len;
        cf_dhcpv4__set_bytes(&so->raw_value, data + pos + 2, use_len);
        so->malformed = malformed;
        if (cf_dhcpv4__is_printable(data + pos + 2, use_len))
            so->decoded_value = cf_dhcpv4__dup_strn(data + pos + 2, use_len);
        else
            so->decoded_value = cf_dhcpv4__hex_encode(data + pos + 2, use_len);

        if (malformed) {
            snprintf(path, sizeof(path),
                     "decoded.relay_agent_information.suboptions[%zu]", n);
            cf_dhcpv4__warn(warnings, "relay_subopt_len_overrun",
                             "relay agent suboption length exceeds remaining bytes",
                             path, data + pos + 2, use_len);
        }

        if (code == 1)
            rai->circuit_id = cf_dhcpv4__dup_str(so->decoded_value);
        else if (code == 2)
            rai->remote_id = cf_dhcpv4__dup_str(so->decoded_value);
        else if (code == 6)
            rai->subscriber_id = cf_dhcpv4__dup_str(so->decoded_value);

        if (n == cap) {
            size_t ncap = cap == 0 ? 4 : cap * 2;
            Cloudflow__V1__DhcpV4RelayAgentSuboption **ni = realloc(arr, ncap * sizeof(*ni));
            if (!ni) {
                cloudflow__v1__dhcp_v4_relay_agent_suboption__free_unpacked(so, NULL);
                break;
            }
            arr = ni;
            cap = ncap;
        }
        arr[n++] = so;

        if (malformed)
            break;
        pos += 2 + sl;
    }

    rai->n_suboptions = n;
    rai->suboptions = arr;
    d->relay_agent_information = rai;
}

/* ---- option 81 client FQDN -------------------------------------------------
 *
 * Layout: flags(1) rcode1(1) rcode2(1) domain-name(variable). If flags bit
 * 0x04 (E, "encoded") is set the domain name is RFC 1035 wire-format labels
 * (decoded via decode_domain_name_list, confined to this option's own
 * bytes); otherwise it is the legacy dotted-ASCII form with no length
 * prefixes and no trailing root label.
 */
static void decode_fqdn(const uint8_t *data, size_t len,
                         Cloudflow__V1__DhcpV4DecodedOptions *d,
                         cf_dhcpv4_warn_list_t *warnings)
{
    Cloudflow__V1__DhcpV4ClientFqdn *fq;
    const uint8_t *namebuf;
    size_t namelen;

    if (len < 3) {
        cf_dhcpv4__warn(warnings, "opt_len_short",
                         "option 81 (FQDN) shorter than its flags/rcode1/rcode2 header",
                         "decoded.client_fqdn", data, len);
        return;
    }

    fq = calloc(1, sizeof(*fq));
    if (!fq)
        return;
    cloudflow__v1__dhcp_v4_client_fqdn__init(fq);

    fq->flags = data[0];
    fq->rcode1 = data[1];
    fq->rcode2 = data[2];

    namebuf = data + 3;
    namelen = len - 3;
    cf_dhcpv4__set_bytes(&fq->raw_domain_name, namebuf, namelen);

    if (namelen > 0) {
        if (fq->flags & 0x04u) {
            char **names = NULL;
            size_t n = 0;

            decode_domain_name_list(namebuf, namelen, &names, &n, warnings,
                                     "decoded.client_fqdn.domain_name");
            if (n > 0)
                fq->domain_name = names[0];
            {
                size_t i;
                for (i = 1; i < n; i++)
                    free(names[i]);
            }
            free(names);
        } else {
            fq->domain_name = cf_dhcpv4__dup_strn(namebuf, namelen);
        }
    }

    d->client_fqdn = fq;
}

/* ---- top-level entry point ------------------------------------------------ */

void cf_dhcpv4__build_decoded(const cf_dhcpv4_concat_map_t *cm,
                               Cloudflow__V1__DhcpV4DecodedOptions **out,
                               cf_dhcpv4_warn_list_t *warnings)
{
    Cloudflow__V1__DhcpV4DecodedOptions *d = calloc(1, sizeof(*d));
    const uint8_t *data;
    size_t len;

    if (!d) {
        *out = NULL;
        return;
    }
    cloudflow__v1__dhcp_v4_decoded_options__init(d);

    /* 53: message type */
    if (cf_dhcpv4__concat_map_has(cm, 53)) {
        data = cf_dhcpv4__concat_map_get(cm, 53, &len);
        if (len >= 1) {
            const char *nm = message_type_name(data[0]);
            d->message_type = message_type_enum(data[0]);
            if (nm[0] != '\0')
                d->message_type_name = cf_dhcpv4__dup_str(nm);
        } else {
            cf_dhcpv4__warn(warnings, "opt_len_short",
                             "option 53 (message type) present but empty",
                             "decoded.message_type", NULL, 0);
        }
    }

    /* 1: subnet mask */
    if (cf_dhcpv4__concat_map_has(cm, 1)) {
        data = cf_dhcpv4__concat_map_get(cm, 1, &len);
        char *s = decode_ipv4_scalar(data, len, "decoded.subnet_mask", warnings);
        if (s)
            d->subnet_mask = s;
    }

    /* 3: routers */
    if (cf_dhcpv4__concat_map_has(cm, 3)) {
        data = cf_dhcpv4__concat_map_get(cm, 3, &len);
        decode_ipv4_list(data, len, &d->routers, &d->n_routers, "decoded.routers",
                          warnings);
    }

    /* 6: domain name servers */
    if (cf_dhcpv4__concat_map_has(cm, 6)) {
        data = cf_dhcpv4__concat_map_get(cm, 6, &len);
        decode_ipv4_list(data, len, &d->domain_name_servers, &d->n_domain_name_servers,
                          "decoded.domain_name_servers", warnings);
    }

    /* 12: host name */
    if (cf_dhcpv4__concat_map_has(cm, 12)) {
        data = cf_dhcpv4__concat_map_get(cm, 12, &len);
        if (len > 0)
            d->host_name = cf_dhcpv4__dup_strn(data, len);
    }

    /* 15: domain name */
    if (cf_dhcpv4__concat_map_has(cm, 15)) {
        data = cf_dhcpv4__concat_map_get(cm, 15, &len);
        if (len > 0)
            d->domain_name = cf_dhcpv4__dup_strn(data, len);
    }

    /* 50: requested IP address */
    if (cf_dhcpv4__concat_map_has(cm, 50)) {
        data = cf_dhcpv4__concat_map_get(cm, 50, &len);
        char *s = decode_ipv4_scalar(data, len, "decoded.requested_ip_address", warnings);
        if (s)
            d->requested_ip_address = s;
    }

    /* 51: IP address lease time */
    if (cf_dhcpv4__concat_map_has(cm, 51)) {
        uint32_t v;
        data = cf_dhcpv4__concat_map_get(cm, 51, &len);
        if (decode_u32(data, len, &v, "decoded.ip_address_lease_time_seconds", warnings))
            d->ip_address_lease_time_seconds = v;
    }

    /* 52: option overload */
    if (cf_dhcpv4__concat_map_has(cm, 52)) {
        data = cf_dhcpv4__concat_map_get(cm, 52, &len);
        if (len >= 1) {
            d->option_overload = data[0];
        } else {
            cf_dhcpv4__warn(warnings, "opt_len_short",
                             "option 52 (overload) present but empty",
                             "decoded.option_overload", NULL, 0);
        }
    }

    /* 54: server identifier */
    if (cf_dhcpv4__concat_map_has(cm, 54)) {
        data = cf_dhcpv4__concat_map_get(cm, 54, &len);
        char *s = decode_ipv4_scalar(data, len, "decoded.server_identifier", warnings);
        if (s)
            d->server_identifier = s;
    }

    /* 55: parameter request list */
    if (cf_dhcpv4__concat_map_has(cm, 55)) {
        data = cf_dhcpv4__concat_map_get(cm, 55, &len);
        if (len > 0) {
            uint32_t *arr = malloc(len * sizeof(*arr));
            if (arr) {
                size_t i;
                for (i = 0; i < len; i++)
                    arr[i] = data[i];
                d->parameter_request_list = arr;
                d->n_parameter_request_list = len;
            }
        }
    }

    /* 56: message */
    if (cf_dhcpv4__concat_map_has(cm, 56)) {
        data = cf_dhcpv4__concat_map_get(cm, 56, &len);
        if (len > 0)
            d->message = cf_dhcpv4__dup_strn(data, len);
    }

    /* 57: max DHCP message size */
    if (cf_dhcpv4__concat_map_has(cm, 57)) {
        uint32_t v;
        data = cf_dhcpv4__concat_map_get(cm, 57, &len);
        if (decode_u16_as_u32(data, len, &v, "decoded.max_dhcp_message_size", warnings))
            d->max_dhcp_message_size = v;
    }

    /* 58: renewal (T1) */
    if (cf_dhcpv4__concat_map_has(cm, 58)) {
        uint32_t v;
        data = cf_dhcpv4__concat_map_get(cm, 58, &len);
        if (decode_u32(data, len, &v, "decoded.renewal_time_t1_seconds", warnings))
            d->renewal_time_t1_seconds = v;
    }

    /* 59: rebinding (T2) */
    if (cf_dhcpv4__concat_map_has(cm, 59)) {
        uint32_t v;
        data = cf_dhcpv4__concat_map_get(cm, 59, &len);
        if (decode_u32(data, len, &v, "decoded.rebinding_time_t2_seconds", warnings))
            d->rebinding_time_t2_seconds = v;
    }

    /* 60: vendor class identifier */
    if (cf_dhcpv4__concat_map_has(cm, 60)) {
        data = cf_dhcpv4__concat_map_get(cm, 60, &len);
        if (len > 0)
            d->vendor_class_identifier = cf_dhcpv4__dup_strn(data, len);
    }

    /* 61: client identifier */
    if (cf_dhcpv4__concat_map_has(cm, 61)) {
        data = cf_dhcpv4__concat_map_get(cm, 61, &len);
        decode_client_id(data, len, d);
    }

    /* 43: vendor-specific information (decoded after 60, which it keys off) */
    if (cf_dhcpv4__concat_map_has(cm, 43)) {
        data = cf_dhcpv4__concat_map_get(cm, 43, &len);
        decode_vendor_specific(
            data, len, d->vendor_class_identifier[0] ? d->vendor_class_identifier : NULL, d);
    }

    /* 66: TFTP server name */
    if (cf_dhcpv4__concat_map_has(cm, 66)) {
        data = cf_dhcpv4__concat_map_get(cm, 66, &len);
        if (len > 0)
            d->tftp_server_name = cf_dhcpv4__dup_strn(data, len);
    }

    /* 67: bootfile name */
    if (cf_dhcpv4__concat_map_has(cm, 67)) {
        data = cf_dhcpv4__concat_map_get(cm, 67, &len);
        if (len > 0)
            d->bootfile_name = cf_dhcpv4__dup_strn(data, len);
    }

    /* 81: client FQDN */
    if (cf_dhcpv4__concat_map_has(cm, 81)) {
        data = cf_dhcpv4__concat_map_get(cm, 81, &len);
        decode_fqdn(data, len, d, warnings);
    }

    /* 82: relay agent information */
    if (cf_dhcpv4__concat_map_has(cm, 82)) {
        data = cf_dhcpv4__concat_map_get(cm, 82, &len);
        decode_relay_agent_info(data, len, d, warnings);
    }

    /* 119: domain search */
    if (cf_dhcpv4__concat_map_has(cm, 119)) {
        data = cf_dhcpv4__concat_map_get(cm, 119, &len);
        decode_domain_name_list(data, len, &d->domain_search, &d->n_domain_search,
                                 warnings, "decoded.domain_search");
    }

    /* 121: classless static routes */
    if (cf_dhcpv4__concat_map_has(cm, 121)) {
        data = cf_dhcpv4__concat_map_get(cm, 121, &len);
        decode_classless_routes(data, len, &d->classless_static_routes,
                                 &d->n_classless_static_routes, warnings,
                                 "decoded.classless_static_routes");
    }

    /* 249: Microsoft classless static routes */
    if (cf_dhcpv4__concat_map_has(cm, 249)) {
        data = cf_dhcpv4__concat_map_get(cm, 249, &len);
        decode_classless_routes(data, len, &d->microsoft_classless_static_routes,
                                 &d->n_microsoft_classless_static_routes, warnings,
                                 "decoded.microsoft_classless_static_routes");
    }

    /* 252: WPAD / proxy autodiscovery */
    if (cf_dhcpv4__concat_map_has(cm, 252)) {
        data = cf_dhcpv4__concat_map_get(cm, 252, &len);
        if (len > 0)
            d->proxy_autodiscovery = cf_dhcpv4__dup_strn(data, len);
    }

    *out = d;
}
