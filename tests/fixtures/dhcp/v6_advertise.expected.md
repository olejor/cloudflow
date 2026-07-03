# v6_advertise

ADVERTISE (reply to v6_solicit) with an IA_NA containing one IAADDR.

- msg-type=2 (ADVERTISE), transaction_id=0x101010
- decoded.server_duid = DUID-LL(3)/hwtype=Ethernet(1) over 02:00:5e:20:00:02
- decoded.client_duid = DUID-LL(3)/hwtype=Ethernet(1) over 02:00:5e:20:00:01
- decoded.assigned_addresses = ["2001:db8::50"] (from IA_NA -> IAADDR)
- interpretation event_type = "dhcpv6.advertise.observed"
