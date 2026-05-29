service:
  name: cloudflow-sink-splunk
  consumer_name: splunk-01

redis:
  endpoints:
    - redis01:6379
    - redis02:6379
    - redis03:6379
  streams:
    - cloudflow:v1:wire:dhcpv4
    - cloudflow:v1:wire:dhcpv6
  consumer_group: sink-splunk
  read_count: 100
  block_ms: 1000

splunk:
  hec_url: https://splunk.example.com:8088/services/collector/event
  hec_token_env: SPLUNK_HEC_TOKEN
  index: network
  sourcetypes:
    dhcpv4: cloudflow:dhcpv4
    dhcpv6: cloudflow:dhcpv6
  batch_size: 500
  flush_interval_ms: 1000
  request_timeout_ms: 5000
