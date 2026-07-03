# v4_overload

DHCPACK using option 52 (overload = 3): the primary options field only
carries options 53 and 52; the "file" field carries options 1 (subnet mask)
and 3 (router), and the "sname" field carries options 6 (DNS) and 12
(hostname).

- xid: 0x77777777
- decoded.option_overload = 3
- decoded.subnet_mask = 255.255.255.0 (recovered from the "file" field)
- decoded.routers = [192.0.2.1] (recovered from the "file" field)
- decoded.domain_name_servers = [192.0.2.53] (recovered from the "sname" field)
- decoded.host_name = "host1" (recovered from the "sname" field)
- raw_options includes entries with source_field = SOURCE_FIELD_FILE and
  SOURCE_FIELD_SNAME in addition to SOURCE_FIELD_OPTIONS
- header.sname_text / header.file_text are both empty: their bytes are
  option TLVs (control-byte option codes), not printable ASCII text
