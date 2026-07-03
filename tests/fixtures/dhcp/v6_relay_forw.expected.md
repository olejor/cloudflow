# v6_relay_forw

RELAY-FORW wrapping a SOLICIT: hop-count/link-address/peer-address in the
outer header, plus an OPTION_RELAY_MSG (9) outer option carrying the inner
SOLICIT's raw bytes verbatim (not recursively parsed in v0.1) and an
OPTION_INTERFACE_ID (18) outer option.

- msg-type=12 (RELAY-FORW), hop_count=0
- header.link_address = "2001:db8:1::1"
- header.peer_address = "fe80::200:5eff:fe20:1"
- raw_options includes code=9 (OPTION_RELAY_MSG) whose raw_value is exactly
  the inner SOLICIT's 44 bytes
  (msg-type=1, transaction_id=0x303030)
- raw_options includes code=18 (OPTION_INTERFACE_ID), raw_value = b"eth0"
- decoded.* fields reflect only the *outer* options (empty/default here --
  the outer message carries no DUID/IA_NA/ORO of its own)
- interpretation event_type = "dhcpv6.relay-forw.observed"
