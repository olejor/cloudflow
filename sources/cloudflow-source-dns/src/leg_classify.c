/* DNS leg classifier (WP-DNS05). See leg_classify.h and docs/dns-source.md
 * (DNS-D7) for the authoritative spec this file implements. */

#include "leg_classify.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#define CF_DNS_SERVER_PORT 53

/* One stored address: version tag plus the 16-byte buffer (v4 in the first 4
 * bytes, matching cf_decap_*_t). Keeping the full 16 bytes for both families
 * keeps the array a flat, cache-friendly POD with no per-entry allocation. */
typedef struct {
    uint8_t ip_version; /* 4 or 6 */
    uint8_t ip[16];
} cf_dns_addr_entry_t;

struct cf_dns_addr_set {
    cf_dns_addr_entry_t *entries;
    size_t count;
    size_t cap;
};

/* Number of address bytes that are significant for a given family. */
static size_t cf_dns_addr_width(uint8_t ip_version)
{
    return ip_version == 4 ? 4u : 16u;
}

cf_dns_addr_set_t *cf_dns_addr_set_new(void)
{
    return calloc(1, sizeof(cf_dns_addr_set_t));
}

void cf_dns_addr_set_free(cf_dns_addr_set_t *set)
{
    if (!set)
        return;
    free(set->entries);
    free(set);
}

/* Grows the backing array by doubling (starting at 8) when full. Returns 1 on
 * success, 0 on allocation failure (the set is left unchanged). */
static int cf_dns_addr_set_reserve(cf_dns_addr_set_t *set)
{
    size_t new_cap;
    cf_dns_addr_entry_t *grown;

    if (set->count < set->cap)
        return 1;

    new_cap = set->cap ? set->cap * 2 : 8;
    grown = realloc(set->entries, new_cap * sizeof(*grown));
    if (!grown)
        return 0;
    set->entries = grown;
    set->cap = new_cap;
    return 1;
}

void cf_dns_addr_set_add_ip(cf_dns_addr_set_t *set, uint8_t ip_version,
                            const uint8_t ip[16])
{
    cf_dns_addr_entry_t *e;

    if (!set || (ip_version != 4 && ip_version != 6))
        return;
    if (!cf_dns_addr_set_reserve(set))
        return;

    e = &set->entries[set->count];
    e->ip_version = ip_version;
    /* Store all 16 bytes; the unused tail for v4 stays zero so the flat entry
     * is deterministic, and matching only ever compares the significant
     * prefix width for the family. */
    memset(e->ip, 0, sizeof(e->ip));
    memcpy(e->ip, ip, cf_dns_addr_width(ip_version));
    set->count++;
}

int cf_dns_addr_set_add_str(cf_dns_addr_set_t *set, const char *ip)
{
    uint8_t buf[16];

    if (!set || !ip)
        return 0;

    if (inet_pton(AF_INET, ip, buf) == 1) {
        cf_dns_addr_set_add_ip(set, 4, buf);
        return 1;
    }
    if (inet_pton(AF_INET6, ip, buf) == 1) {
        cf_dns_addr_set_add_ip(set, 6, buf);
        return 1;
    }
    return 0; /* malformed / not an IPv4 or IPv6 literal */
}

int cf_dns_addr_set_contains(const cf_dns_addr_set_t *set, uint8_t ip_version,
                             const uint8_t ip[16])
{
    size_t width, i;

    if (!set || (ip_version != 4 && ip_version != 6))
        return 0;

    width = cf_dns_addr_width(ip_version);
    for (i = 0; i < set->count; i++) {
        const cf_dns_addr_entry_t *e = &set->entries[i];
        /* Version-aware: a v4 address never matches a v6 entry (or vice
         * versa) even if the significant bytes coincide. */
        if (e->ip_version == ip_version &&
            memcmp(e->ip, ip, width) == 0)
            return 1;
    }
    return 0;
}

Cloudflow__V1__DnsLeg cf_dns_classify_leg(const cf_dns_leg_config_t *cfg,
                                          uint8_t ip_version,
                                          const uint8_t src_ip[16],
                                          uint16_t src_port,
                                          const uint8_t dst_ip[16],
                                          uint16_t dst_port,
                                          cf_dns_capture_dir_t direction,
                                          int *local_is_server_out)
{
    const uint8_t *server_ip;
    const cf_dns_addr_set_t *local = cfg ? cfg->local_addrs : NULL;
    const cf_dns_addr_set_t *backend = cfg ? cfg->backend_addrs : NULL;
    int local_is_server = 0;
    Cloudflow__V1__DnsLeg role;

    /* Step 1 (DNS-D7): the server side is the endpoint whose port is 53. If
     * neither endpoint or both endpoints are on :53, the server side is
     * indeterminate -- source/destination port alone cannot tell a client
     * (ephemeral -> :53) apart from a recursion upstream (also ephemeral ->
     * :53), so we do not guess. */
    if (dst_port == CF_DNS_SERVER_PORT && src_port != CF_DNS_SERVER_PORT) {
        server_ip = dst_ip; /* query direction: client -> server:53 */
    } else if (src_port == CF_DNS_SERVER_PORT && dst_port != CF_DNS_SERVER_PORT) {
        server_ip = src_ip; /* response direction: server:53 -> client */
    } else {
        /* Indeterminate. Capture direction is explicitly NOT used to break
         * this tie: DNS-D7 forbids direction from being the sole signal, and
         * here the address sets give us nothing, so the honest answer is
         * UNKNOWN (counted by the caller). */
        if (local_is_server_out)
            *local_is_server_out = 0;
        return CLOUDFLOW__V1__DNS_LEG__DNS_LEG_UNKNOWN;
    }

    /* Step 2 (DNS-D7): local-IP-set membership is authoritative. */
    if (cf_dns_addr_set_contains(local, ip_version, server_ip)) {
        /* Our local server is being queried by some client. */
        role = CLOUDFLOW__V1__DNS_LEG__DNS_LEG_CLIENT_FACING;
        local_is_server = 1;
    } else if (cf_dns_addr_set_contains(backend, ip_version, server_ip)) {
        /* A remote server we front (e.g. dnsdist -> pdns): the backend set is
         * the only thing separating this from an internet-upstream query. */
        role = CLOUDFLOW__V1__DNS_LEG__DNS_LEG_BACKEND;
    } else {
        /* Remote server not in the backend set: recursion out to the wider
         * internet (an authoritative or a public resolver). */
        role = CLOUDFLOW__V1__DNS_LEG__DNS_LEG_RECURSION_UPSTREAM;
    }

    /* Step 3 (DNS-D7): capture direction is a cross-check only. On a
     * SPAN/mirror capture it is CF_DNS_DIR_UNKNOWN and carries no information;
     * even when known it may only confirm or lower confidence in the decision
     * above (e.g. a CLIENT_FACING query is expected INGRESS, its response
     * EGRESS), and is never permitted to override the authoritative
     * address-set classification. v0.2 surfaces no confidence field, so the
     * cross-check is a no-op on the returned role -- we consume `direction`
     * here to make that contract explicit rather than silently ignore it. */
    (void)direction;

    if (local_is_server_out)
        *local_is_server_out = local_is_server;
    return role;
}
