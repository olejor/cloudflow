# v4_offer

DHCPOFFER with subnet mask, router, two DNS servers, lease time, T1, T2.

- xid: 0x11111111
- op=2 (BOOTREPLY), yiaddr=192.0.2.50, siaddr=192.0.2.2
- decoded.message_type = OFFER
- decoded.subnet_mask = 255.255.255.0
- decoded.routers = [192.0.2.1]
- decoded.domain_name_servers = [192.0.2.53, 198.51.100.53]
- decoded.ip_address_lease_time_seconds = 86400
- decoded.server_identifier = 192.0.2.2
- decoded.renewal_time_t1_seconds = 43200
- decoded.rebinding_time_t2_seconds = 75600
- interpretation.event_type = "dhcpv4.offer.observed"
- interpretation.lease_address = "192.0.2.50" (yiaddr, since message type is OFFER)
