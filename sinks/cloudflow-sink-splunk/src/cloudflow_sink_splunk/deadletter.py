"""Dead-letter stream writer.

Stream cloudflow:v1:deadletter:sink-splunk, entry fields reason /
origin_stream / origin_id / error / payload (docs/design/04-sink-splunk.md,
"Dead-letter stream"). MAXLEN ~ 100000.

Callers must call write() and let it raise before XACKing the original
entry: the dead-letter XADD has to succeed before the source entry is
acknowledged, so that if the dead-letter write itself fails, the original
stays pending and is retried (at-least-once, never silent loss).
"""

from __future__ import annotations

from typing import Optional

from .metrics import JsonLogger, Metrics

STREAM_NAME = "cloudflow:v1:deadletter:sink-splunk"
MAXLEN = 100000

REASON_DECODE_ERROR = "decode_error"
REASON_HEC_REJECTED = "hec_rejected"

_ERROR_FIELD_MAX_LEN = 2000


class DeadLetterWriter:
    def __init__(
        self,
        redis_client,
        metrics: Metrics,
        logger: Optional[JsonLogger] = None,
        stream: str = STREAM_NAME,
        maxlen: int = MAXLEN,
    ):
        self.redis = redis_client
        self.metrics = metrics
        self.logger = logger or JsonLogger("cloudflow-sink-splunk")
        self.stream = stream
        self.maxlen = maxlen

    def write(
        self,
        reason: str,
        origin_stream: str,
        origin_id: str,
        error: str,
        payload: bytes,
    ) -> None:
        """XADD the dead-letter entry. Raises on failure; does not catch."""
        fields = {
            "reason": reason,
            "origin_stream": origin_stream,
            "origin_id": origin_id,
            "error": (error or "")[:_ERROR_FIELD_MAX_LEN],
            "payload": payload or b"",
        }
        self.redis.xadd(self.stream, fields, maxlen=self.maxlen, approximate=True)
        self.metrics.inc("deadletter_total")
        self.logger.info(
            "dead_lettered",
            reason=reason,
            origin_stream=origin_stream,
            origin_id=origin_id,
        )
