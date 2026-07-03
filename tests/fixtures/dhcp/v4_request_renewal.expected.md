# v4_request_renewal

Unicast DHCPREQUEST with no requested-ip (50) and no server-id (54) option
-- the renewal heuristic (see cf_dhcpv4.c's build_interpretation comment):
a REQUEST missing both of those, sent unicast (broadcast flag clear), is
classified as a lease renewal (RENEWING state per RFC 2131) rather than a
rebind.

- xid: 0x33333333
- op=1, ciaddr=192.0.2.51 (the lease being renewed), flags=0x0000 (unicast)
- decoded.message_type = REQUEST
- decoded.requested_ip_address = "" (absent)
- decoded.server_identifier = "" (absent)
- interpretation.event_type = "dhcpv4.request.observed"
- interpretation.is_broadcast = false
- interpretation.is_renewal = true
- interpretation.is_rebind = false
