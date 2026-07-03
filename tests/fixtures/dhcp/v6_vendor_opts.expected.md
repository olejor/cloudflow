# v6_vendor_opts

INFORMATION-REQUEST carrying option 17 (vendor-specific information) with an
enterprise number and two suboptions (one printable, one binary).

- msg-type=11 (INFORMATION-REQUEST), transaction_id=0x404040
- decoded.vendor_options.enterprise_number = 99999
- decoded.vendor_options.suboptions[0]: code=1, decoded_value="cloudflow-fixture"
- decoded.vendor_options.suboptions[1]: code=2, raw_value=de:ad:be:ef (hex, not printable)
- interpretation event_type = "dhcpv6.information-request.observed"
