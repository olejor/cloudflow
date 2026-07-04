# Failure modes

CloudFlow must make data-loss and retry decisions explicit. This document
originally posed these as open questions; v0.1 (WP-01..WP-17) has now
implemented and tested the behaviors below. Each section states the decided
policy, the counter(s) that make it observable, and the test that proves it.

## Internal queue pressure (rx-reader -> formatter -> redis-producer)

**Decided (D9).** Every bounded SPSC `cf_queue_t` has an explicit `on_full`
policy, set per queue in config (`queues.on_full`):

- `drop_newest` (default) -- the incoming item is discarded, the queue is
  left as-is;
- `drop_oldest` -- the oldest queued item is discarded to make room;
- `block` -- the producer side blocks until space is available (used only
  where a stall is preferable to loss; never on the rx-reader in production,
  since blocking there risks kernel ring drops upstream instead).

Every drop increments a named counter (`rx_queue_drop_total` /
`formatter_queue_drop_total`, per D8) reported in the periodic structured
stats line, so queue pressure is always visible, never silent. All three
policies (including `block`'s unblock-via-drain path) are covered by
`sources/cloudflow-source-dhcp`'s `rx_reader_test.c` CUnit suite
(`cf_queue_push_policy` exercised directly).

## Redis unavailable (producer side, WP-09)

**Decided.** The redis-producer retries a failed `XADD` pipeline flush
**once** with reconnect (D3: fail over to the next configured endpoint on
connect failure), then, if that retry also fails, the batch is dropped and
every event in it increments `events_lost_total` -- there is no local spool
and no unbounded blocking; Redis is the only durable buffer in v0.1, so once
it is unreachable past one retry, loss is counted rather than hidden.
`redis_reconnects_total` tracks reconnect attempts separately from loss.
Proven by `libs/cloudflow-redis/tests/cf_redis_producer_test.c` (test B:
`CLIENT KILL` mid-stream, then push more; `events_lost_total +
delivered == total pushed`, `redis_reconnects_total >= 1`) and test C
(`cf_redis_producer_stop()` drains the queue before returning -- a clean
stop never contributes to loss).

## Splunk unavailable / rejecting (sink side, WP-17)

**Decided**, matching the original recommendation:

- messages stay pending in the `sink-splunk` Redis consumer group; nothing
  is ACKed until delivery is confirmed (or the entry is confirmed
  dead-lettered);
- network errors, timeouts, HTTP 429, and 5xx responses back off
  exponentially (1 s doubling to a 30 s cap) and retry the batch
  **indefinitely** -- consumption pauses rather than drops, because Redis is
  the durable buffer by design (this is why `redis.maxlen_approx` /
  `MAXLEN ~` exist: unbounded pending growth is a capacity-planning problem,
  not a correctness one);
  - other HTTP 4xx responses bisect the batch (recursive split, floor
    batch=1) to isolate exactly the poison event(s): those are
    dead-lettered with `reason=hec_rejected` and ACKed, the rest of the
    batch is delivered normally;
- `splunk_retry_total`, `splunk_delivery_errors_total`, and
  `redis_stream_lag` (last id vs. last-delivered, per stream) are the
  signals to alert on for growing backlog / consumer lag.

Exercised by the sink's own `tests/test_hec.c` (5xx-then-2xx retried and
acked once; a 3-event batch with one poison event under HTTP 400 bisects to
2 delivered + 1 dead-lettered).

## Malformed / undecodable events (protobuf decode failure, WP-17)

**Decided.** Any entry that fails the encoding/schema check
(`encoding == protobuf`, `schema == cloudflow.v1.CloudFlowEvent`) or fails
`protobuf-c` unpacking is routed to the dead-letter stream
`cloudflow:v1:deadletter:sink-splunk` with `reason=decode_error`, then
ACKed on the origin stream -- redelivery of an unparseable payload would
fail identically forever, so at-least-once here means "at least
dead-lettered," not "retried forever." The dead-letter `XADD` must succeed
**before** the origin entry is ACKed; if the dead-letter write itself fails,
the origin entry stays pending and is retried (never silent loss either
way). `protobuf_decode_errors_total` and `deadletter_total` count this path.

Proven end-to-end by `scripts/run-integration-tests.sh`'s poison-path case
(WP-14, step 7): a hand-`XADD`ed garbage-payload entry on
`cloudflow:v1:wire:dhcpv4` (valid `schema`/`encoding`/`event_type` fields,
undecodable `payload`) is run through `cloudflow-sink-splunk --once`; the
script asserts the entry lands in the dead-letter stream with
`reason=decode_error` and `origin_stream=cloudflow:v1:wire:dhcpv4`, and that
the `sink-splunk` consumer group shows 0 pending afterward. The two
`*_malformed_optlen` DHCP fixtures are the *parser*-level analogue one layer
up the pipeline: those payloads decode to a `CloudFlowEvent` successfully
(best-effort option resync, per their `.expected.md`) with
`parser_warnings` set, rather than being dropped -- malformed does not
always mean undecodable, and only the latter is dead-lettered here.

## Queue pressure (general)

All internal queues are bounded (D9, above); no service in the pipeline
buffers unboundedly in memory. Queue pressure is always visible through the
structured stats line's depth gauges and drop counters (D8).

## Event replay / duplicate handling

**Decided (D5).** `event_id` is a deterministic hash of
`(source_host, capture_interface, observed_time_unix_nano, raw frame bytes)`,
so replaying the same capture (or redelivering an unacked entry after a
crash) reproduces the same `event_id` rather than minting a new one --
downstream (Splunk) duplicate suppression can key on it. This is what makes
`scripts/run-integration-tests.sh` safe to run repeatedly against a fresh
Redis: the fixed `source_host`/`capture_interface` in its generated test
config, combined with the fixtures' fixed capture timestamps, make every run
produce identical `event_id`s.

## DNS correlation-table failure modes (v0.2, implemented)

The DNS source (`docs/dns-source.md`) adds one more stateful component: a
bounded pending-query table between the parser and the correlation stage.
Its failure modes follow the same explicit-policy, no-silent-loss discipline
as the rest of the pipeline, with bounded-loss counters on every eviction:

- **Table full.** A parsed query that cannot be inserted because the table
  is at capacity is handled per the configured `dns.on_table_full` policy
  (default `drop_newest`), counted by `dns_pending_drop_total`.
- **Timeout eviction.** A query with no matching response within
  `dns.query_timeout_ms` (default 5000 ms) is evicted and emitted as
  `dns.query.unanswered`, counted by `dns_query_unanswered_total` — this is
  a normal, expected outcome (loss, drop, or a real gap), not an error.
- **Collision eviction.** A hash-table slot occupied by a still-live older
  query, displaced by a new query before its own timeout (key collision or
  fast port reuse), is evicted as `dns.query.unanswered` and separately
  counted by `dns_pending_evicted_collision_total` so it can be
  distinguished from an ordinary timeout.

All three counters land in the same structured stats line as the DHCP
source's counters. See `docs/dns-source.md`'s "Correlation stage" section
for the full design.
