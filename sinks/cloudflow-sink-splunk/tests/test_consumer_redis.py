"""Consumer/ack logic against a real local Redis.

docs/design/04-sink-splunk.md acceptance criteria:

- producing 100 events then running --once --stdout prints 100 mapped
  events and leaves 0 pending after ack;
- killing the sink mid-batch and re-running re-delivers unacked entries
  exactly (XAUTOCLAIM path covered by a second consumer name);
- a poison entry -> dead-letter with reason=decode_error, XACKed.

Per the harness fixture in conftest.py, these tests transparently skip if
redis-server is not available.
"""

from __future__ import annotations

import io

import fixtures
import pytest

from cloudflow_sink_splunk import config, deadletter as deadletter_mod, metrics as metrics_mod
from cloudflow_sink_splunk.consumer import Consumer
from cloudflow_sink_splunk.deadletter import DeadLetterWriter
from cloudflow_sink_splunk.hec import StdoutSink

STREAM = "cloudflow:v1:wire:dhcpv4"
GROUP = "sink-splunk"


def _redis_config(streams=(STREAM,), read_count=100, block_ms=100):
    return config.RedisConfig(
        endpoints=["127.0.0.1:0"],  # unused directly; tests construct the client themselves
        streams=list(streams),
        consumer_group=GROUP,
        read_count=read_count,
        block_ms=block_ms,
    )


def _splunk_config(**overrides):
    defaults = dict(
        hec_url="https://splunk.example.com:8088/services/collector/event",
        hec_token_env="SPLUNK_HEC_TOKEN",
        index="network",
        sourcetypes={"dhcpv4": "cloudflow:dhcpv4", "dhcpv6": "cloudflow:dhcpv6"},
    )
    defaults.update(overrides)
    return config.SplunkConfig(**defaults)


def _xadd_event(redis_client, stream, cf_event, *, schema="cloudflow.v1.CloudFlowEvent", encoding="protobuf"):
    return redis_client.xadd(
        stream,
        {
            "schema": schema,
            "version": "1",
            "encoding": encoding,
            "payload": cf_event.SerializeToString(),
        },
    )


def _make_consumer(redis_client, consumer_name, sink, dl_metrics=None, min_idle_ms=0, streams=(STREAM,)):
    m = dl_metrics or metrics_mod.Metrics("test")
    dl = DeadLetterWriter(redis_client, metrics=m)
    return Consumer(
        redis_client=redis_client,
        redis_config=_redis_config(streams=streams),
        splunk_config=_splunk_config(),
        sink=sink,
        deadletter=dl,
        metrics=m,
        consumer_name=consumer_name,
        min_idle_ms=min_idle_ms,
    )


def test_100_events_processed_and_acked(redis_client):
    for _ in range(100):
        _xadd_event(redis_client, STREAM, fixtures.dhcpv4_discover_event())

    buf = io.StringIO()
    sink = StdoutSink(stream=buf)
    consumer = _make_consumer(redis_client, "splunk-01", sink)

    consumer.run_once()

    lines = [l for l in buf.getvalue().splitlines() if l.strip()]
    assert len(lines) == 100

    pending = redis_client.xpending(STREAM, GROUP)
    assert pending["pending"] == 0


def test_xautoclaim_redelivers_after_crash(redis_client):
    for _ in range(10):
        _xadd_event(redis_client, STREAM, fixtures.dhcpv4_discover_event())

    # consumer1 "crashes": it reads (which marks entries pending under its
    # name) but never flushes/acks.
    buf1 = io.StringIO()
    sink1 = StdoutSink(stream=buf1)
    consumer1 = _make_consumer(redis_client, "splunk-crashed", sink1)
    consumer1.ensure_groups()
    consumer1._reclaim_all()
    consumer1._read_new(block_ms=None)  # reads into consumer1's batch, never flushed
    assert buf1.getvalue() == ""  # nothing printed: crashed before flush

    pending_after_crash = redis_client.xpending(STREAM, GROUP)
    assert pending_after_crash["pending"] == 10

    # consumer2 (different consumer name) reclaims via XAUTOCLAIM. Real
    # production min-idle is 60s (docs/design/04-sink-splunk.md); tests pass
    # min_idle_ms=0 so the reclaim is immediate instead of waiting 60s.
    buf2 = io.StringIO()
    sink2 = StdoutSink(stream=buf2)
    consumer2 = _make_consumer(redis_client, "splunk-02", sink2, min_idle_ms=0)
    consumer2.run_once()

    lines = [l for l in buf2.getvalue().splitlines() if l.strip()]
    assert len(lines) == 10

    pending_after_reclaim = redis_client.xpending(STREAM, GROUP)
    assert pending_after_reclaim["pending"] == 0


def test_poison_entry_is_dead_lettered_and_acked(redis_client):
    good = fixtures.dhcpv4_discover_event()
    _xadd_event(redis_client, STREAM, good)
    # Malformed payload: valid entry fields, but bytes that are not a
    # parseable CloudFlowEvent.
    _xadd_event(
        redis_client,
        STREAM,
        good,
        schema="cloudflow.v1.CloudFlowEvent",
        encoding="protobuf",
    )
    poison_id = redis_client.xadd(
        STREAM,
        {
            "schema": "cloudflow.v1.CloudFlowEvent",
            "version": "1",
            "encoding": "protobuf",
            "payload": b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
        },
    )

    buf = io.StringIO()
    sink = StdoutSink(stream=buf)
    m = metrics_mod.Metrics("test")
    consumer = _make_consumer(redis_client, "splunk-01", sink, dl_metrics=m)
    consumer.run_once()

    pending = redis_client.xpending(STREAM, GROUP)
    assert pending["pending"] == 0

    dl_entries = redis_client.xrange(deadletter_mod.STREAM_NAME, "-", "+")
    assert len(dl_entries) == 1
    dl_id, dl_fields = dl_entries[0]
    assert dl_fields[b"reason"] == b"decode_error"
    assert dl_fields[b"origin_id"] == poison_id
    assert dl_fields[b"origin_stream"].decode() == STREAM
    assert dl_fields[b"payload"] == b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"

    lines = [l for l in buf.getvalue().splitlines() if l.strip()]
    assert len(lines) == 2  # the 2 well-formed entries were delivered normally


def test_wrong_schema_or_encoding_is_dead_lettered(redis_client):
    good = fixtures.dhcpv4_discover_event()
    bad_id = _xadd_event(redis_client, STREAM, good, schema="cloudflow.v1.EventEnvelope")

    buf = io.StringIO()
    sink = StdoutSink(stream=buf)
    m = metrics_mod.Metrics("test")
    consumer = _make_consumer(redis_client, "splunk-01", sink, dl_metrics=m)
    consumer.run_once()

    pending = redis_client.xpending(STREAM, GROUP)
    assert pending["pending"] == 0

    dl_entries = redis_client.xrange(deadletter_mod.STREAM_NAME, "-", "+")
    assert len(dl_entries) == 1
    assert dl_entries[0][1][b"reason"] == b"decode_error"
    assert dl_entries[0][1][b"origin_id"] == bad_id
    assert m.snapshot()["protobuf_decode_errors_total"] == 1


def test_ensure_groups_ignores_busygroup(redis_client):
    consumer = _make_consumer(redis_client, "splunk-01", StdoutSink(stream=io.StringIO()))
    consumer.ensure_groups()
    consumer.ensure_groups()  # second call must not raise (BUSYGROUP ignored)
