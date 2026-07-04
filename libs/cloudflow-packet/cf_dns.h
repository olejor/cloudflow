#ifndef CF_DNS_H
#define CF_DNS_H

#include <stddef.h>
#include <stdint.h>

#include "cloudflow/v1/dns.pb-c.h"

#include "cf_parse_util.h"

/* DNS message parser (WP-DNS03). Pure computation: a bare DNS message in ->
 * a heap-allocated Cloudflow__V1__DnsMessage tree out. No sockets, no Redis,
 * no threads, no TCP length prefix (the caller strips udp/tcp framing first;
 * see docs/dns-source.md, DNS-D1). Every read is bounds-checked against the
 * message buffer, and name decompression is hardened against forward/self
 * pointers, pointer loops, and over-length names (WP-DNS09 fuzzes this).
 *
 * The returned tree is built directly (not via protobuf-c's __unpack()), but
 * every nested message is calloc()'d and initialized via its generated
 * __init(), every `char *` field is the immutable protobuf_c_empty_string
 * sentinel or a malloc()'d string, and every repeated field / bytes field is
 * malloc()'d -- so the generated, descriptor-driven
 * cloudflow__v1__dns_message__free_unpacked(*out, NULL) frees the whole tree
 * correctly, exactly like cf_dhcpv4.c's DhcpV4PacketEvent.
 */

/* Parses a bare DNS message (starting at the 12-byte header; NO TCP length
 * prefix). Returns 1 if a usable message was produced (possibly with
 * warnings), 0 if unparseable (e.g. < 12 bytes). On success *out is a fresh
 * Cloudflow__V1__DnsMessage owned by the caller and freeable with
 * cloudflow__v1__dns_message__free_unpacked(*out, NULL). Warnings are appended
 * to `warnings`. */
int cf_dns_parse(const uint8_t *msg, size_t msg_len,
                 Cloudflow__V1__DnsMessage **out, cf_warn_list_t *warnings);

#endif
