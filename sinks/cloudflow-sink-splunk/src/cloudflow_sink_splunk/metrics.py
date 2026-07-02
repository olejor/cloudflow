"""Structured logging (Convention 7) and counters/periodic stats line (D8).

Both live here because they share the same "one JSON object per line on
stderr" contract: normal log records carry `ts`/`level`/`service`/`msg` plus
context, and the periodic stats line is just another record whose `msg` is
"stats" and whose context is the counter snapshot.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class JsonLogger:
    """One JSON object per line on stderr. Never pass secrets as fields."""

    def __init__(self, service: str, stream=None):
        self.service = service
        self.stream = stream if stream is not None else sys.stderr

    def log(self, level: str, msg: str, **fields: Any) -> None:
        record = {"ts": _now_iso(), "level": level, "service": self.service, "msg": msg}
        record.update(fields)
        print(json.dumps(record, sort_keys=True, default=str), file=self.stream, flush=True)

    def debug(self, msg: str, **fields: Any) -> None:
        self.log("debug", msg, **fields)

    def info(self, msg: str, **fields: Any) -> None:
        self.log("info", msg, **fields)

    def warning(self, msg: str, **fields: Any) -> None:
        self.log("warning", msg, **fields)

    def error(self, msg: str, **fields: Any) -> None:
        self.log("error", msg, **fields)


# Counter names from docs/design/04-sink-splunk.md.
COUNTER_NAMES = (
    "splunk_delivery_total",
    "splunk_delivery_errors_total",
    "splunk_retry_total",
    "deadletter_total",
    "protobuf_decode_errors_total",
)


class Metrics:
    """Atomic-ish counters (GIL-protected) + periodic JSON stats line."""

    def __init__(self, service: str, logger: Optional[JsonLogger] = None):
        self.service = service
        self.logger = logger or JsonLogger(service)
        self._lock = threading.Lock()
        self._counters: Dict[str, int] = defaultdict(int)
        self._last_values: Dict[str, Any] = {}
        self._latencies_ms = []
        self._stream_lag: Dict[str, Optional[int]] = {}
        self._last_emit = time.monotonic()

    def inc(self, name: str, value: int = 1) -> None:
        with self._lock:
            self._counters[name] += value

    def set_last(self, name: str, value: Any) -> None:
        with self._lock:
            self._last_values[name] = value

    def record_delivery_latency_ms(self, ms: float) -> None:
        with self._lock:
            self._latencies_ms.append(ms)
            self._last_values["splunk_delivery_latency_ms_last"] = ms

    def set_stream_lag(self, stream: str, lag: Optional[int]) -> None:
        with self._lock:
            self._stream_lag[stream] = lag

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            data: Dict[str, Any] = {name: self._counters.get(name, 0) for name in COUNTER_NAMES}
            # include any counters not in the known list too (forward compatible)
            for name, value in self._counters.items():
                data.setdefault(name, value)
            data.update(self._last_values)
            if self._latencies_ms:
                data["splunk_delivery_latency_ms_avg"] = sum(self._latencies_ms) / len(
                    self._latencies_ms
                )
                self._latencies_ms = []
            else:
                data.setdefault("splunk_delivery_latency_ms_avg", 0)
            data["redis_stream_lag"] = dict(self._stream_lag)
            return data

    def emit(self) -> None:
        self.logger.log("info", "stats", **self.snapshot())
        self._last_emit = time.monotonic()

    def maybe_emit(self, interval_s: float = 10.0) -> None:
        if time.monotonic() - self._last_emit >= interval_s:
            self.emit()
