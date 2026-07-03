# v6_solicit

SOLICIT with client DUID (1), ORO (6), and an IA_NA (3) hint (no IAADDR yet
-- the client does not have an address to request).

- msg-type=1 (SOLICIT), transaction_id=0x101010
- decoded.client_duid = DUID-LL(3)/hwtype=Ethernet(1) over 02:00:5e:20:00:01
- decoded.option_request_option_codes = [23, 24, 31]
- decoded.assigned_addresses is empty (the IA_NA carries no IAADDR)
- interpretation event_type = "dhcpv6.solicit.observed"
