# v4_long_option

DHCPACK with option 121 (classless static routes) long enough (360 bytes)
to require an RFC 3396 split into two consecutive option-121 instances
(255 + 105 bytes) in raw_options; decoding must concatenate them before
parsing route entries.

- xid: 0x88888888
- raw_options has exactly 2 entries with code == 121, both with
  source_field = SOURCE_FIELD_OPTIONS and long_option_fragment = true
- decoded.classless_static_routes has 40 entries:
  - [0]: destination_prefix_length=32, destination="192.0.2.0", router="198.51.100.1"
  - [39]: destination_prefix_length=32, destination="192.0.2.39", router="198.51.100.1"
