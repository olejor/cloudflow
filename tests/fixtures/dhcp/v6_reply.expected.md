# v6_reply

REPLY (reply to v6_request) with the assigned address and server DUID.

- msg-type=7 (REPLY), transaction_id=0x202020
- decoded.server_duid = DUID-LL(3)/hwtype=Ethernet(1) over 02:00:5e:20:00:02
- decoded.assigned_addresses = ["2001:db8::50"]
- interpretation event_type = "dhcpv6.reply.observed"
