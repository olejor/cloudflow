# v6_request

REQUEST carrying client DUID, the server DUID echoed from v6_advertise, ORO,
and an IA_NA requesting the offered address.

- msg-type=3 (REQUEST), transaction_id=0x202020
- decoded.client_duid / decoded.server_duid both present
- decoded.option_request_option_codes = [23, 24]
- decoded.assigned_addresses = ["2001:db8::50"]
- interpretation event_type = "dhcpv6.request.observed"
