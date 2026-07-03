# v4_relayed_ack

DHCPACK forwarded through a relay agent: giaddr set, option 82 (relay agent
information) with circuit-id, remote-id, and subscriber-id suboptions.

- xid: 0x55555555
- op=2, hops=1, giaddr=198.51.100.1, yiaddr=198.51.100.50
- decoded.message_type = ACK
- decoded.relay_agent_information.circuit_id = "eth01" (option 1, printable -> text)
- decoded.relay_agent_information.remote_id = hex("02:00:5e:10:00:0a") (option 2, binary MAC -> hex)
- decoded.relay_agent_information.subscriber_id = "sub-001" (option 6, printable -> text)
- interpretation.event_type = "dhcpv4.ack.observed"
- interpretation.is_relayed = true
