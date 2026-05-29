# Splunk output

The Splunk sink consumes protobuf CloudFlow events and emits JSON to Splunk HEC.

Recommended sourcetypes:

```text
cloudflow:dhcpv4
cloudflow:dhcpv6
```

Required preservation:

- `event_id`
- `event_type`
- `source_host`
- `capture_interface`
- `observation_method`
- `observed_time_unix_nano`
- DHCP protocol payload

The sink should use observed packet time as the Splunk event timestamp when practical.

Do not index opaque protobuf payloads directly unless a deliberate Splunk-side decoding strategy exists.
