# cloudflow-source-dns

Wire-observed DNS source (CloudFlow v0.2). Captures udp/53 and tcp/53, parses
DNS messages, correlates each query with its response into a
`cloudflow.v1.CloudFlowEvent` (`DnsTransactionEvent` payload) carrying per-leg
RTT and a leg role, and writes to `cloudflow:v1:wire:dns`.

The authoritative design is `docs/dns-source.md` (decisions `DNS-D1..9`, the
correlation-stage spec, and the `WP-DNSnn` roadmap). This source reuses the
v0.1 libraries — `cloudflow-core`, `cloudflow-codec`, `cloudflow-packet`
(`cf_decap_udp`/`cf_decap_tcp` + `cf_dns_parse`), and `cloudflow-redis` — and
follows the same three-thread, bounded-queue shape as the DHCP source, plus a
stateful correlation stage between parse and encode.

## Pipeline

```text
rx-reader -> [pkt queue] -> parse + correlate -> [event queue] -> redis-producer
```

Parse and correlate share one thread so the bounded pending-query table needs
no locking (see `docs/dns-source.md`, "Correlation stage").

## Running

```sh
# Live capture (needs CAP_NET_RAW to open the AF_PACKET ring):
cloudflow-source-dns -c /etc/cloudflow/dns-source.yaml

# Offline replay of a classic pcap through the whole pipeline, then drain and
# exit (integration/M-DNS1 mode):
cloudflow-source-dns -c /etc/cloudflow/dns-source.yaml \
    --replay tests/fixtures/dns/q_a_query.pcap

cloudflow-source-dns --version   # print version and exit
cloudflow-source-dns -h          # usage
```

`-c <config>` is required in both modes (it supplies the Redis endpoints, queue
sizing, and the correlation/classifier knobs even when the input is a pcap;
`--replay` only swaps the input stage). A `SIGINT`/`SIGTERM` triggers a clean
reverse-order shutdown (reader → event stage → producer) and exits 0. If Redis
is unreachable the producer logs a backoff warning and keeps the pipeline
running; on shutdown any still-queued events are counted lost, never silently
dropped.

## Configuration

The YAML schema is documented, field by field, in
`configs/examples/dns-source.yaml`. Sections: `service` (name / source_host),
`capture` (interface / method / snaplen / filter), `queues` (the two bounded
SPSC queue capacities + `on_full` policy), `redis` (endpoints, `maxlen_approx`,
XADD batch/flush), `dns` (the DNS-D5/D7/D8 knobs: `pending_table_capacity`,
`query_timeout_ms`, `on_table_full`, `local_service_addresses`,
`backend_addresses`, `emit_policy` + `sample_denominator`), and `stats`
(`interval_s` / `reset_on_report`). Missing keys fall back to the defaults in
that example; unknown keys are logged and ignored.

The DNS source writes exactly one stream, `cloudflow:v1:wire:dns`
(`CF_STREAM_DNS`); `redis.expected_stream_dns` and `capture.filter` are used for
validation/logging only, not as overrides (a mismatch is logged as a warning) —
the builtin VLAN-aware udp/53 + tcp/53 cBPF filter is always used.

**Secrets are never in the YAML.** Redis/Splunk credentials come from the
process environment (the systemd unit's `EnvironmentFile`). Three non-secret
environment overrides are honored on top of the file: `CF_REDIS_ENDPOINTS`
(comma-separated `host:port` list), `CF_INTERFACE`, and `CF_SOURCE_HOST`.

> **Leg classifier note (DNS-D7).** The local-service address set is currently
> the configured `dns.local_service_addresses` list only; the "auto-derive
> local addresses from the capture interface" helper is not implemented yet, so
> list this host's DNS service IPs explicitly.

## systemd

`systemd/cloudflow-source-dns.service` runs the binary as the unprivileged
`cloudflow` user with `AmbientCapabilities=CAP_NET_RAW` (open the capture
socket) and `CAP_SYS_NICE` (best-effort rx-reader priority; optional),
`NoNewPrivileges=yes`, and `Restart=on-failure`. Secrets are loaded from
`EnvironmentFile=/etc/cloudflow/dns-source.env` (a root-owned, mode-0600
`KEY=VALUE` file). Install the binary to `/usr/local/bin`, the config to
`/etc/cloudflow/dns-source.yaml`, then `systemctl enable --now
cloudflow-source-dns`.

The unit is sandboxed (project review G4): `ProtectSystem=strict` +
`PrivateTmp=yes` make the whole filesystem read-only apart from a private
`/tmp` (the daemon writes nothing to disk — logs go to journald — so no
`ReadWritePaths` are declared), plus `ProtectHome`, `ProtectControlGroups`,
`ProtectKernel{Modules,Tunables}`, `LockPersonality`, `MemoryDenyWriteExecute`
(the TPACKET_V3 ring is mmap'd read/write, never executable, so W^X is safe),
`RestrictSUIDSGID`, `RestrictNamespaces`,
`SystemCallArchitectures=native`, and `SystemCallFilter=@system-service`
(covers the `mmap`/`socket`/`setsockopt`/`bind`/`recvmsg` the capture ring
needs). Being a capture *source*, it keeps `CAP_NET_RAW` (+`CAP_SYS_NICE`) via a
tight `CapabilityBoundingSet=CAP_NET_RAW CAP_SYS_NICE` and allows
`RestrictAddressFamilies=AF_PACKET AF_INET AF_INET6 AF_UNIX` — sinks are stricter
(no raw socket, empty capability set, no `AF_PACKET`).

## SELinux

`selinux/cloudflow_source_dns.{te,fc}` confine the daemon to the
`cloudflow_source_dns_t` domain on RHEL 9: `CAP_NET_RAW`/`CAP_SYS_NICE` for the
capture ring, best-effort `SCHED_FIFO`, outbound TCP to Redis, and read-only
access to a private `cloudflow_source_dns_conf_t` type that labels
`dns-source.yaml` and the secrets `dns-source.env` (nothing else can read
them). Build with `make -C selinux` and install per `docs/selinux.md`, which
also covers the permissive-first rollout.

## Layout and build

```text
src/     pipeline modules: correlation.c, leg_classify.c, ... (main.c is the app entry)
tests/   one CUnit binary per tests/*_test.c
```

The `Makefile` is wildcard-driven: every `src/*.c` except `main.c` is archived
into `libcloudflow-source-dns.a`, and every `tests/*_test.c` builds as its own
CUnit binary in a plain and an ASan+UBSan variant — so a new module drops in
without editing the Makefile.

```sh
make -C sources/cloudflow-source-dns all        # build the library (+ binary once main.c lands)
make -C sources/cloudflow-source-dns test        # run every CUnit suite
make -C sources/cloudflow-source-dns test-asan    # ASan+UBSan variants
```

Correlation and classifier tests replay the sanitized query/response pcap
pairs under `tests/fixtures/dns/` (see `docs/dns-source.md`, "Fixture and test
policy").
