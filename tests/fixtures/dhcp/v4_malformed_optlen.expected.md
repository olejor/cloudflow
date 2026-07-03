# v4_malformed_optlen

Hand-built (not scapy-encoded) payload: a valid option 53 (DISCOVER)
followed by an option 50 (requested IP) that declares a 4-byte value but
the payload ends after only 1 of those bytes, with no end marker. Exercises
the "never trust lengths" / best-resync requirement.

- xid: 0x99999999
- Parsing succeeds (non-NULL event) despite the malformed trailing option.
- decoded.message_type = DISCOVER (recovered -- option 53 came first and
  was intact)
- raw_options' last entry: code=50, malformed=true, raw_value = the single
  available byte (0xAA), length=1
- parser_warnings is non-empty and includes a warning with
  code="opt_len_overrun" and field_path="raw_options[1]"
- interpretation.event_type = "dhcpv4.discover.observed"
