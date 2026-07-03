# v6_malformed_optlen

Hand-built (not scapy-encoded) payload: a valid OPTION_CLIENTID (1) followed
by an OPTION_ORO (6) that declares a 4-byte value but the payload ends after
only 1 of those bytes, with no further options. Exercises the "never trust
lengths" / best-resync requirement.

- msg-type=1 (SOLICIT), transaction_id=0x505050
- Parsing succeeds (non-NULL event) despite the malformed trailing option.
- decoded.client_duid is still recovered (option 1 came first and was intact)
- raw_options' last entry: code=6, malformed=true, length=1
- parser_warnings is non-empty and includes a warning with
  code="opt_len_overrun" and field_path="raw_options[1]"
- interpretation event_type = "dhcpv6.solicit.observed"
