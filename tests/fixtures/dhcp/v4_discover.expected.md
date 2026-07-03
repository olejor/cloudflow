# v4_discover

Basic DHCPDISCOVER, exercising options 53/55/57/61.

- xid: 0x11111111
- op=1 (BOOTREQUEST), htype=1, hlen=6, flags=0x8000 (broadcast)
- ciaddr=yiaddr=siaddr=giaddr=0.0.0.0
- chaddr -> chaddr_mac = 02:00:5e:10:00:01
- decoded.message_type = DISCOVER, message_type_name = "DISCOVER"
- decoded.parameter_request_list = [1, 3, 6, 15]
- decoded.max_dhcp_message_size = 1500
- decoded.client_identifier_raw = 01:02005e100001, client_identifier_text = "02:00:5e:10:00:01"
- interpretation.event_type = "dhcpv4.discover.observed"
- interpretation.is_broadcast = true
- interpretation.is_relayed = false
- interpretation.normalized_client_key = client-id hex ("01" + MAC hex)
