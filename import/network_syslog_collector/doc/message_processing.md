# Message Processing and Forwarding

## Message Format

Messages received from different clients may follow various formats. Some clients implement a variant of ***RFC-3164***, while others use ***RFC-5424***. In some cases, clients that follow ***RFC-5424*** also include SDATA fields.

Currently, the only commonality across messages is the first 4 bytes, which represent the message's ***priority***. This priority can be decoded to extract the facility and severity of the message.

## Handling Non-ASCII Characters

Some messages, likely due to human error, may contain non-printable or non-ASCII characters. These characters must be removed before forwarding the messages.

## Example messages

```text
<185>1 Allvis-EDR [HAG@43119 MAC="deadbeefdead"] [EDR@43119 MAC="deadcafebabe" VENDOR="android-dhcp-9"]

<185>1 2018-04-19T21:02:29+02:00 1.2.3.4 NDD 8711 - [HAG@43119 MAC="cafedeadbeef"] [NDD@43119 MAC="deaddeadbeef"]

<185>1 2015-05-26T15:23:21+02:00 1.2.3.4 NDD 884 - [HAG@43119 MAC="deadcafebabe"] [NDD@43119 MAC="deadbeefdead"]

<142> 2016-08-08 11:00:30 Power Button

<142> 2017-07-13 17:22:43 Power Outage

<7>Oct  9 12:51:28 kernel: [1992360.497000] [wifi0] FWLOG: [24728725] WAL_DBGID_FAST_WAKE_REQUEST ( 0xce )

<7>Oct  9 12:51:29 kernel: [2524781.504000] [wifi0] FWLOG: [32430621] WAL_DBGID_FAST_WAKE_REQUEST ( 0x11 )

<30>1 2024-10-09T12:52:46+02:00  ZTR69 8432 - [HAG@43119 MAC=""] [STATUS] cwmp_sess_handler(): ****[TR-069]System Reboot Due To Reboot by ACS****

<30>Oct  9 13:03:28 deadbeefdead [HAG@43119 MAC="deadcafebabe"] : dnsmasq-dhcp[6686]: DHCPACK(br-lan1) 192.168.10.157 00:00:00:04:00:b5 foobars-airport-time-capsule
```

## Message Forwarding

There are two types of forwarding mechanisms when using Redis Cluster:

1. "At least once" (***XADD***): Used for critical data that must be handled reliably.
2. "At most once" (***SPUBLISH***): Used for less critical data, where message loss is acceptable.

```json
{
    "version": 1,                           // Protocol version (defines the version of this format)
    "raddr": "123.123.123.123|foo1::dead",  // Address of the client
    "ts": 1728473192.123,                   // Timestamp when the message was received
    "payload": "the raw message"            // Full message sent by the client
}
```

## Forwarding Rules

The table below outlines the rules for forwarding messages. In this table, * represents a wildcard that can match any value:

| Guarantee |  Topic          | Matcher              | Priority       | Facility    | Severity   | Pattern | Example message |
|------------|-----------------|----------------------|----------------|-------------|------------|---------|-----------------|
| XADD | syslog:ndd | Priority | 185 | * | * | * | <185>1 2018-04-19T21:02:29+02:00 1.2.3.4 NDD 8711 - [HAG@43119 MAC="cafedeadbeef"] [NDD@43119 MAC="deaddeadbeef"] |
| SPUBLISH | syslog:dhcp:ack | Priority + Pattern | * | 3 | <=6 | ^.*DHCPACK | <30>Oct  9 13:03:28 deadbeefdead [HAG@43119 MAC="deadcafebabe"] : dnsmasq-dhcp[6686]: DHCPACK(br-lan1) 192.168.10.157 00:00:00:04:00:b5 foobars-airport-time-capsule |
| SPUBLISH | syslog:sev:emerg | Severity | * | * | 0 | * | * |
| SPUBLISH | syslog:sev:alert | Severity | * | * | 1 | * | * |

## Severities

| Severity Code | Severity Description |
|---------------|----------------------|
| 0             | Emergency            |
| 1             | Alert                |
| 2             | Critical             |
| 3             | Error                |
| 4             | Warning              |
| 5             | Notice               |
| 6             | Informational        |
| 7             | Debug                |

## Facilities

| Facility Code | Facility Description             |
|---------------|----------------------------------|
| 0             | kernel messages                  |
| 1             | user-level messages              |
| 2             | mail system                      |
| 3             | system daemons                   |
| 4             | security/authorization messages  |
| 5             | messages generated internally by syslogd |
| 6             | line printer subsystem           |
| 7             | network news subsystem           |
| 8             | UUCP subsystem                   |
| 9             | clock daemon                     |
| 10            | security/authorization messages  |
| 11            | FTP daemon                       |
| 12            | NTP subsystem                    |
| 13            | log audit                        |
| 14            | log alert                        |
| 15            | clock daemon                     |
| 16            | local0                           |
| 17            | local1                           |
| 18            | local2                           |
| 19            | local3                           |
| 20            | local4                           |
| 21            | local5                           |
| 22            | local6                           |
| 23            | local7                           |
