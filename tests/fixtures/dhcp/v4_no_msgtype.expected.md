# v4_no_msgtype

BOOTP-ish packet (valid magic cookie and one ordinary option) but with no
option 53 (message type) at all.

- xid: 0xaaaaaaaa
- decoded.message_type = MESSAGE_TYPE_UNSPECIFIED, message_type_name = ""
- interpretation.event_type = "dhcpv4.packet.observed"
