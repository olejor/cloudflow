#ifndef CF_IPFMT_H
#define CF_IPFMT_H

#include <stdint.h>

/* Reentrant MAC/IP address formatting -- unlike the legacy helpers in
 * import/, these write into a caller-supplied buffer instead of a static
 * one, so they are safe to call from multiple threads concurrently.
 */

/* Formats `mac` as lowercase colon-separated hex, e.g. "02:00:5e:01:02:03".
 * `out` must be at least 18 bytes (17 chars + NUL). */
void cf_format_mac(char out[18], const uint8_t mac[6]);

/* Formats an IPv4 (ip_version == 4, address in ip[0..4)) or IPv6
 * (ip_version == 6, address in ip[0..16)) address in its standard text
 * representation (IPv6 using the RFC 5952 zero-run compression, matching
 * inet_ntop()). `out` must be at least 46 bytes (INET6_ADDRSTRLEN). Writes
 * an empty string if `ip_version` is neither 4 nor 6. */
void cf_format_ip(char out[46], uint8_t ip_version, const uint8_t ip[16]);

#endif
