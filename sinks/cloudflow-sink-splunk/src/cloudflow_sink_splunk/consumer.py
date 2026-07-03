"""Redis consumer-group logic (docs/design/04-sink-splunk.md, "Consumer behavior").

- On startup: XGROUP CREATE <stream> sink-splunk 0 MKSTREAM for each
  configured stream (BUSYGROUP ignored -- the group already exists).
- Loop: first reclaim stale pending entries (XAUTOCLAIM min-idle-time=60s,
  count-limited) so a crashed consumer's messages are re-processed, then
  XREADGROUP ... COUNT read_count BLOCK block_ms STREAMS <streams...> >.
- Decode each entry: check encoding=="protobuf" and
  schema=="cloudflow.v1.CloudFlowEvent", then parse payload. Any decode
  failure -> dead-letter, then XACK the original (count
  protobuf_decode_errors_total; re-delivery would fail identically
  forever).
- Transform to HEC events, hand to the batcher (hec.Sink). XACK only entries
  whose batch got a 2xx (or after confirmed dead-lettering). Batches carry
  the originating (stream, entry_id) for exactly this purpose.
- SIGTERM: stop reading, flush the in-flight batch once, XACK what
  succeeded, exit. Unacked entries simply remain pending (at-least-once).
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Dict, List, Optional

import redis

from cloudflow.v1.envelope_pb2 import CloudFlowEvent

from . import transform
from .deadletter import REASON_DECODE_ERROR, REASON_HEC_REJECTED, DeadLetterWriter
from .hec import BatchItem, Sink
from .metrics import JsonLogger, Metrics

REQUIRED_ENCODING = b"protobuf"
REQUIRED_SCHEMA = b"cloudflow.v1.CloudFlowEvent"

# Spec default (docs/design/04-sink-splunk.md): reclaim entries idle >= 60s.
# Kept as a constructor parameter (not YAML-configurable) so tests can make
# XAUTOCLAIM reclaim immediately instead of waiting a real 60 seconds.
DEFAULT_MIN_IDLE_MS = 60_000


def _to_text(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def connect_redis(redis_config, **client_kwargs) -> "redis.Redis":
    """D3: standalone Redis; try endpoints in order, use the first that works."""
    last_exc: Optional[Exception] = None
    for endpoint in redis_config.endpoints:
        host, _, port = endpoint.partition(":")
        port = int(port) if port else 6379
        client = redis.Redis(host=host, port=port, decode_responses=False, **client_kwargs)
        try:
            client.ping()
            return client
        except redis.exceptions.RedisError as exc:
            last_exc = exc
            continue
    raise ConnectionError(
        f"could not connect to any redis endpoint in {redis_config.endpoints!r}: {last_exc}"
    )


class Consumer:
    def __init__(
        self,
        redis_client,
        redis_config,
        splunk_config,
        sink: Sink,
        deadletter: DeadLetterWriter,
        metrics: Metrics,
        consumer_name: str,
        logger: Optional[JsonLogger] = None,
        min_idle_ms: int = DEFAULT_MIN_IDLE_MS,
    ):
        self.r = redis_client
        self.cfg = redis_config
        self.splunk_cfg = splunk_config
        self.sink = sink
        self.dl = deadletter
        self.metrics = metrics
        self.consumer_name = consumer_name
        self.log = logger or JsonLogger("cloudflow-sink-splunk")
        self.min_idle_ms = min_idle_ms

        self._stop = False
        self._autoclaim_cursor: Dict[str, bytes] = {s: b"0-0" for s in self.cfg.streams}
        self._batch: List[BatchItem] = []
        self._last_flush = time.monotonic()

    def stop(self) -> None:
        self._stop = True

    # -- setup -----------------------------------------------------------

    def ensure_groups(self) -> None:
        for stream in self.cfg.streams:
            try:
                self.r.xgroup_create(stream, self.cfg.consumer_group, id="0", mkstream=True)
            except redis.exceptions.ResponseError as exc:
                if "BUSYGROUP" not in str(exc):
                    raise

    # -- reading -----------------------------------------------------------

    def _reclaim_stream(self, stream: str):
        cursor = self._autoclaim_cursor.get(stream, b"0-0")
        next_cursor, entries, _deleted = self.r.xautoclaim(
            stream,
            self.cfg.consumer_group,
            self.consumer_name,
            min_idle_time=self.min_idle_ms,
            start_id=cursor,
            count=self.cfg.read_count,
        )
        self._autoclaim_cursor[stream] = next_cursor
        return entries

    def _reclaim_all(self) -> None:
        for stream in self.cfg.streams:
            for entry_id, fields in self._reclaim_stream(stream):
                self._process_entry(_to_text(stream), _to_text(entry_id), fields)

    def _read_new(self, block_ms: Optional[int]) -> int:
        resp = self.r.xreadgroup(
            self.cfg.consumer_group,
            self.consumer_name,
            {stream: ">" for stream in self.cfg.streams},
            count=self.cfg.read_count,
            block=block_ms,
        )
        count = 0
        for stream, entries in resp or []:
            stream_name = _to_text(stream)
            for entry_id, fields in entries:
                self._process_entry(stream_name, _to_text(entry_id), fields)
                count += 1
        return count

    # -- processing --------------------------------------------------------

    def _dead_letter_and_ack(
        self, stream: str, entry_id: str, reason: str, error: str, payload: bytes
    ) -> None:
        # Must succeed before ack (docs/design/04-sink-splunk.md,
        # "Dead-letter stream"): if this raises, the caller must not ack.
        self.dl.write(reason, stream, entry_id, error, payload)
        self.r.xack(stream, self.cfg.consumer_group, entry_id)

    def _process_entry(self, stream: str, entry_id: str, fields: dict) -> None:
        encoding = fields.get(b"encoding")
        schema = fields.get(b"schema")
        payload = fields.get(b"payload")

        if encoding != REQUIRED_ENCODING or schema != REQUIRED_SCHEMA or payload is None:
            self.metrics.inc("protobuf_decode_errors_total")
            self._dead_letter_and_ack(
                stream,
                entry_id,
                REASON_DECODE_ERROR,
                f"invalid entry fields: encoding={encoding!r} schema={schema!r}",
                payload or b"",
            )
            return

        cf_event = CloudFlowEvent()
        try:
            cf_event.ParseFromString(payload)
        except Exception as exc:  # noqa: BLE001 - any parse failure is a decode error
            self.metrics.inc("protobuf_decode_errors_total")
            self._dead_letter_and_ack(
                stream, entry_id, REASON_DECODE_ERROR, f"protobuf parse error: {exc}", payload
            )
            return

        try:
            line = transform.render_hec_line(cf_event, stream, self.splunk_cfg)
        except Exception as exc:  # noqa: BLE001
            self.metrics.inc("protobuf_decode_errors_total")
            self._dead_letter_and_ack(
                stream, entry_id, REASON_DECODE_ERROR, f"transform error: {exc}", payload
            )
            return

        self._batch.append(BatchItem(stream=stream, entry_id=entry_id, line=line, payload=payload))

    # -- delivery ------------------------------------------------------------

    def _flush_batch(self) -> None:
        self._last_flush = time.monotonic()
        if not self._batch:
            return
        batch, self._batch = self._batch, []

        delivered, poison = self.sink.send_batch(batch)

        acks: Dict[str, List[str]] = defaultdict(list)
        for item in delivered:
            acks[item.stream].append(item.entry_id)

        for item, error in poison:
            self.dl.write(REASON_HEC_REJECTED, item.stream, item.entry_id, error, item.payload)
            acks[item.stream].append(item.entry_id)

        for stream, ids in acks.items():
            self.r.xack(stream, self.cfg.consumer_group, *ids)

    def _should_flush(self) -> bool:
        if len(self._batch) >= self.splunk_cfg.batch_size:
            return True
        if self._batch and (time.monotonic() - self._last_flush) * 1000 >= self.splunk_cfg.flush_interval_ms:
            return True
        return False

    def _maybe_flush(self) -> None:
        if self._should_flush():
            self._flush_batch()

    # -- run loops -----------------------------------------------------------

    def run_once(self) -> None:
        """Process what is pending, then return. Used by --once and tests."""
        self.ensure_groups()
        self._reclaim_all()
        self._maybe_flush()
        # Non-blocking reads (block=None) so we drain exactly what is
        # currently available rather than waiting for more.
        while True:
            n = self._read_new(block_ms=None)
            self._maybe_flush()
            if n == 0:
                break
        self._flush_batch()
        self._update_stream_lag()

    def _update_stream_lag(self) -> None:
        # redis_stream_lag metric (per docs/design/04-sink-splunk.md): per
        # stream, XINFO STREAM last id vs. last delivered. Redis >= 7.0
        # computes this for us as XINFO GROUPS' "lag" field; fall back to
        # None (unknown) on older servers or any transient error.
        for stream in self.cfg.streams:
            try:
                groups = self.r.xinfo_groups(stream)
            except redis.exceptions.RedisError:
                self.metrics.set_stream_lag(stream, None)
                continue
            lag = None
            for group in groups:
                name = group.get(b"name") or group.get("name")
                if _to_text(name) == self.cfg.consumer_group:
                    lag = group.get(b"lag", group.get("lag"))
                    break
            self.metrics.set_stream_lag(stream, lag)

    def run_forever(self) -> None:
        """Consume until stop() is called (SIGTERM handler), then exit."""
        self.ensure_groups()
        while not self._stop:
            self._reclaim_all()
            self._maybe_flush()
            if self._stop:
                break
            self._read_new(block_ms=self.cfg.block_ms)
            self._maybe_flush()
            self._update_stream_lag()
            self.metrics.maybe_emit()
        # Shutdown: flush the in-flight batch once, ack what succeeded, exit.
        self._flush_batch()
        self._update_stream_lag()
        self.metrics.emit()
