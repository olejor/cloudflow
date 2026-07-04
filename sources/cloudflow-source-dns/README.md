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
