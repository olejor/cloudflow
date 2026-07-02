/* libs/cloudflow-packet/cf_ipfmt.c
 *
 * Reentrant MAC/IP formatting. See cf_ipfmt.h.
 */

#include "cf_ipfmt.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

void cf_format_mac(char out[18], const uint8_t mac[6])
{
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
              mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void cf_format_ip(char out[46], uint8_t ip_version, const uint8_t ip[16])
{
    if (ip_version == 4) {
        struct in_addr addr;
        memcpy(&addr, ip, sizeof(addr));
        if (inet_ntop(AF_INET, &addr, out, 46) == NULL)
            out[0] = '\0';
    } else if (ip_version == 6) {
        struct in6_addr addr;
        memcpy(&addr, ip, sizeof(addr));
        if (inet_ntop(AF_INET6, &addr, out, 46) == NULL)
            out[0] = '\0';
    } else {
        out[0] = '\0';
    }
}
