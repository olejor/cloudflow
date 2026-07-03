# WP-15 XADD benchmark -- first baseline

Recorded by running `make bench` (`scripts/benchmark-xadd.sh` ->
`tests/performance/bench_xadd`) end to end in this environment.

- **Date:** 2026-07-03
- **Redis:** `redis-server v=7.0.15 sha=00000000:0 malloc=jemalloc-5.3.0 bits=64
  build=b30e82fcf6da7c56` (private instance on port 6398, `--save ''`, no
  persistence, single node, default config otherwise)
- **Hardware:** `Intel(R) Xeon(R) Processor @ 2.80GHz`, 4 logical CPUs
  (`nproc` = 4), `hypervisor` CPU flag present.

**This is a shared/virtualized container, not dedicated hardware.** The CPU
model string is a generic cloud/VM label (no model number), a `hypervisor`
flag is set, and the benchmark runs alongside whatever else the host is
doing at the time. Treat every number below as a rough order-of-magnitude
baseline for catching regressions on *this same environment*, not as a
representative figure for production capacity planning -- run-to-run
variance of 10-20% on a noisy host would not be surprising, and absolute
throughput will differ (probably substantially, in either direction) on real
server hardware, a pinned CPU, or a quieter machine.

## Results

Matrix: payload size in {512, 2048, 8192} bytes x producer pipeline size in
{1, 64, 512}, 3s duration per cell, default flush interval (100ms), Redis
and `bench_xadd` both local (loopback), `bench_xadd` compiled with the
standard hardened toolchain flags (`mk/toolchain.mk`), no `MAXLEN` trim on
`XADD` (script issues a raw `DEL` of both DHCP streams before every run
instead, to keep Redis memory bounded across the matrix while keeping
per-run figures untrimmed).

| payload_size | pipeline | events/sec | MB/sec  | avg_xadd_latency_us | reconnects | events_lost_total |
|-------------:|---------:|-----------:|--------:|---------------------:|-----------:|-------------------:|
| 512          | 1        | 12166.4    | 5.941   | 75.171               | 0          | 0                  |
| 512          | 64       | 91445.0    | 44.651  | 5.957                | 0          | 0                  |
| 512          | 512      | 99204.8    | 48.440  | 5.275                | 0          | 0                  |
| 2048         | 1        | 11450.6    | 22.364  | 79.992               | 0          | 0                  |
| 2048         | 64       | 52846.9    | 103.217 | 14.124               | 0          | 0                  |
| 2048         | 512      | 51234.2    | 100.067 | 14.284               | 0          | 0                  |
| 8192         | 1        | 13073.6    | 102.138 | 68.939               | 0          | 0                  |
| 8192         | 64       | 17863.3    | 139.557 | 50.015               | 0          | 0                  |
| 8192         | 512      | 22207.2    | 173.494 | 37.549               | 0          | 0                  |

No reconnects and no lost events in any cell (`events_lost_total` is always
0, as required -- `bench_xadd` exits nonzero otherwise, and the whole run
exited 0).

## pipeline=1 vs pipeline=512 delta

For the default 2048-byte payload (the row `scripts/benchmark-xadd.sh`'s
sanity check keys off of):

- pipeline=1: 11450.6 events/sec, avg XADD latency 79.99 us (one
  request-response round trip per event -- latency-bound, not
  throughput-bound)
- pipeline=512: 51234.2 events/sec, avg XADD latency 14.28 us

**Ratio: 4.47x** -- comfortably clears the >2x sanity threshold the script
asserts, confirming pipelining is actually engaged (the per-event latency
drops roughly in proportion, since with pipelining the round-trip cost is
amortized over up to 512 in-flight `XADD`s instead of paid per event).

The 512- and 8192-byte payload rows show the same qualitative pattern
(pipeline=64/512 several x faster than pipeline=1), though at 8192 bytes the
gain from 64 -> 512 is smaller and throughput growth partially trades off
against MB/sec -- the run is trending toward this host's network/loopback
and Redis-server-thread bandwidth ceiling rather than latency, which is the
expected shape once pipelining has already erased most of the per-event
round-trip cost.

## Reproducing

```
make bench
```

runs the full matrix (9 cells, ~30s total on this host) via
`scripts/benchmark-xadd.sh`, which starts and tears down its own private
Redis instance (port 6398) and does not touch any other Redis instance
(e.g. `scripts/run-local-redis.sh`'s dev container) on the machine.
