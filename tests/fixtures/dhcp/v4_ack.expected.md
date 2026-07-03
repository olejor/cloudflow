# v4_ack

DHCPACK (reply to v4_request_renewal's REQUEST) carrying option 81 (client
FQDN, wire/RFC 1035-label encoding) and option 119 (domain search list,
RFC 1035 compressed within the option's own concatenated bytes).

- xid: 0x33333333
- op=2, yiaddr=192.0.2.51, siaddr=192.0.2.2
- decoded.message_type = ACK
- decoded.client_fqdn.flags = 0x04 (E bit set: wire-format encoding)
- decoded.client_fqdn.domain_name = "client1.example.com"
- decoded.domain_search = ["eng.example.com", "example.com"]
  (the second name is a compression pointer back into the first)
- interpretation.event_type = "dhcpv4.ack.observed"
- interpretation.lease_address = "192.0.2.51"
