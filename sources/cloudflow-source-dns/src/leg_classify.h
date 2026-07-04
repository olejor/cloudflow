#ifndef CF_LEG_CLASSIFY_H
#define CF_LEG_CLASSIFY_H

#include <stdint.h>

#include "cloudflow/v1/dns.pb-c.h"

/* DNS leg classifier (WP-DNS05, DNS-D7 in docs/dns-source.md).
 *
 * A pure decision function: given one observed DNS packet's endpoints (src/dst
 * IP + port), the capture direction, and two configured address sets (the
 * local service addresses and the backend addresses), it assigns the packet a
 * DnsLeg role and reports which endpoint is the server (the DNS-D6 correlation
 * key's `local_is_server` field).
 *
 * No sockets, no threads, no globals, and no allocation on the hot path -- the
 * only allocation is the address-set backing array (grown in the `_add`
 * helpers, released in `_free`). The classifier itself (cf_dns_classify_leg)
 * allocates nothing.
 *
 * DNS-D7 priority (implemented verbatim by cf_dns_classify_leg):
 *   1. Identify the server side = the endpoint whose port is 53. If neither or
 *      both ports are 53, the server side is indeterminate.
 *   2. Local-IP-set membership is authoritative:
 *        server IP in the local service set -> DNS_LEG_CLIENT_FACING,
 *                                              local_is_server = 1;
 *        server IP remote and in the backend set -> DNS_LEG_BACKEND,
 *                                              local_is_server = 0;
 *        server IP remote and not in the backend set ->
 *                                              DNS_LEG_RECURSION_UPSTREAM,
 *                                              local_is_server = 0;
 *        server side indeterminate -> DNS_LEG_UNKNOWN.
 *   3. Capture direction is a cross-check / tie-break only, never the sole
 *      signal: source/destination port alone cannot distinguish a client from
 *      a recursion upstream -- both are `ephemeral -> :53` -- which is exactly
 *      why the local/backend address sets are required. Direction is therefore
 *      never allowed to override an authoritative address-set decision.
 */

/* A set of exact service addresses. v0.2 is exact-match only; CIDR/prefix
 * matching (so a whole subnet can be a local or backend set) is a documented
 * future extension. Backed by a small owned array, grown on demand. The set
 * may hold a mix of IPv4 and IPv6 addresses; matching is version-aware, so a
 * v4 address never matches the identical bytes stored as v6. */
typedef struct cf_dns_addr_set cf_dns_addr_set_t;

/* Allocates an empty address set. Returns NULL on allocation failure. */
cf_dns_addr_set_t *cf_dns_addr_set_new(void);

/* Frees an address set and its backing array. NULL is a no-op. */
void cf_dns_addr_set_free(cf_dns_addr_set_t *set);

/* Parses `ip` (e.g. "192.0.2.1" or "2001:db8::1") with inet_pton and adds it
 * to the set. Returns 1 on success, 0 if `ip` is malformed / not a valid
 * IPv4 or IPv6 literal (in which case the set is unchanged) or on allocation
 * failure. */
int cf_dns_addr_set_add_str(cf_dns_addr_set_t *set, const char *ip);

/* Adds a raw address: `ip_version` is 4 or 6, `ip` holds the address with v4
 * in the first 4 bytes (the cloudflow-packet convention). A version that is
 * neither 4 nor 6 is ignored. */
void cf_dns_addr_set_add_ip(cf_dns_addr_set_t *set, uint8_t ip_version,
                            const uint8_t ip[16]);

/* Version-aware exact-match membership test: 1 if (`ip_version`, `ip`) is in
 * the set (comparing 4 bytes for v4, 16 for v6), else 0. A NULL set is empty
 * (returns 0). */
int cf_dns_addr_set_contains(const cf_dns_addr_set_t *set, uint8_t ip_version,
                             const uint8_t ip[16]);

/* An ordered address -> label map (WP-DNS11a, a DNS-D7 extension). Parallel to
 * cf_dns_addr_set but each stored address also carries an operator-defined
 * service-role label (e.g. "dnsdist" / "recursor" / "authoritative"). It is
 * built from a config list of {addresses[], label} groups and consulted with
 * the transaction's *server-side* address, so a transaction's service_role is
 * the label the operator assigned to whichever DNS service owns :53 -- a config
 * dimension that does NOT change the leg `role` decided by cf_dns_classify_leg.
 *
 * Version-aware exact match like cf_dns_addr_set (a v4 address never matches a
 * v6 entry). Lookup is first-match-wins in insertion order. The map owns a copy
 * of every label string; cf_dns_role_map_free releases the backing array and
 * every label (ASan-clean). */
typedef struct cf_dns_role_map cf_dns_role_map_t;

/* Allocates an empty role map. Returns NULL on allocation failure. */
cf_dns_role_map_t *cf_dns_role_map_new(void);

/* Frees a role map, its backing array, and every owned label. NULL is a no-op. */
void cf_dns_role_map_free(cf_dns_role_map_t *map);

/* Parses `ip` with inet_pton and adds it mapped to `label` (copied). Returns 1
 * on success, 0 if `ip` is malformed / not a valid IPv4 or IPv6 literal, if
 * `label` is NULL/empty, or on allocation failure (the map is left unchanged).
 * A later entry for the same address does not replace an earlier one -- lookup
 * returns the first match in insertion order. */
int cf_dns_role_map_add_str(cf_dns_role_map_t *map, const char *ip, const char *label);

/* Adds a raw address (same convention as cf_dns_addr_set_add_ip) mapped to
 * `label` (copied). A version that is neither 4 nor 6, a NULL/empty label, or
 * an allocation failure is ignored (the map is left unchanged). */
void cf_dns_role_map_add_ip(cf_dns_role_map_t *map, uint8_t ip_version,
                            const uint8_t ip[16], const char *label);

/* Version-aware exact-match lookup for a server-side IP: returns the borrowed
 * label string for (`ip_version`, `ip`) (owned by the map, valid until it is
 * freed) or NULL if the address is not mapped. A NULL map returns NULL. */
const char *cf_dns_role_lookup(const cf_dns_role_map_t *map, uint8_t ip_version,
                               const uint8_t ip[16]);

/* Capture direction from the rx ring (DNS-D7 step 2). UNKNOWN is the honest
 * value on SPAN/mirror captures where kernel packet direction is meaningless;
 * it is why the address sets, not direction, are authoritative. */
typedef enum {
    CF_DNS_DIR_UNKNOWN = 0,
    CF_DNS_DIR_INGRESS = 1,
    CF_DNS_DIR_EGRESS = 2
} cf_dns_capture_dir_t;

typedef struct {
    const cf_dns_addr_set_t *local_addrs;   /* auto-derived + config; may be empty/NULL */
    const cf_dns_addr_set_t *backend_addrs; /* config; may be empty/NULL */
} cf_dns_leg_config_t;

/* Classifies one observed DNS packet per DNS-D7. `ip_version` is 4 or 6 and
 * applies to both endpoints; src/dst IP use the v4-in-first-4-bytes
 * convention. Ports are host-order. `direction` is a cross-check only and
 * never overrides the address-set decision. Fills *local_is_server_out (0 or
 * 1, for the DNS-D6 key) when non-NULL and returns the DnsLeg role. */
Cloudflow__V1__DnsLeg cf_dns_classify_leg(const cf_dns_leg_config_t *cfg,
                                          uint8_t ip_version,
                                          const uint8_t src_ip[16],
                                          uint16_t src_port,
                                          const uint8_t dst_ip[16],
                                          uint16_t dst_port,
                                          cf_dns_capture_dir_t direction,
                                          int *local_is_server_out);

#endif
