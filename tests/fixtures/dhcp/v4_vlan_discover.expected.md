# v4_vlan_discover

Same DHCPDISCOVER as v4_discover, but 802.1Q tagged (VLAN 100) -- exercises
WP-05's cf_decap VLAN handling as well as the WP-06 parser; the DHCPv4
fields themselves are unaffected by the VLAN tag (cf_decap strips it before
cf_dhcpv4_parse ever sees the payload).

- VLAN id: 100
- xid: 0x66666666
- decoded.message_type = DISCOVER
- interpretation.event_type = "dhcpv4.discover.observed"
