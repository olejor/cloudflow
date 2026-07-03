# v4_nak

DHCPNAK carrying option 56 (message).

- xid: 0x44444444
- op=2, yiaddr=0.0.0.0 (NAK never carries a lease address)
- decoded.message_type = NAK
- decoded.server_identifier = 192.0.2.2
- decoded.message = "requested address not available on this subnet"
- interpretation.event_type = "dhcpv4.nak.observed"
- interpretation.lease_address = "" (NAK is not OFFER/ACK)
