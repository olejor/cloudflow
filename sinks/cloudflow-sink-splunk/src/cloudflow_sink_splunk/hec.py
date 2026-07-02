"""Batched Splunk HEC delivery with retry/backoff/bisect (D6, D8).

Retry policy (docs/design/04-sink-splunk.md, "HEC delivery and retry"):

- network errors, timeouts, HTTP 429 and 5xx: exponential backoff starting
  at 1s, doubling to a 30s cap, retried indefinitely. Consumption pauses
  while this happens -- Redis is the buffer, that is by design
  (docs/failure-modes.md).
- HTTP 4xx other than 429: the batch is bisected recursively (floor batch
  size 1) to isolate the poison event(s); poison events are reported back to
  the caller for dead-lettering + XACK, the rest are retried/delivered
  normally.

The sink's own stdout mode (--stdout) uses a different Sink implementation
(StdoutSink, below) with the same send_batch() contract, so consumer.py does
not need to know which one it is talking to.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, List, Optional, Sequence, Tuple

import requests

from .metrics import JsonLogger, Metrics

# Never include this in a log record.
_AUTH_HEADER = "Authorization"


@dataclass
class BatchItem:
    stream: str
    entry_id: str
    line: str
    payload: bytes


PoisonItem = Tuple[BatchItem, str]  # (item, error message)


class Sink:
    """Common interface for HecClient and StdoutSink."""

    def send_batch(
        self, items: Sequence[BatchItem]
    ) -> Tuple[List[BatchItem], List[PoisonItem]]:
        raise NotImplementedError


class StdoutSink(Sink):
    """--stdout mode: print HEC-shaped JSON lines instead of POSTing.

    Every line "delivers" successfully (there is nothing to reject); this
    lets consumer.py treat --stdout and real HEC delivery uniformly.
    """

    def __init__(self, stream=None, metrics: Optional[Metrics] = None):
        import sys

        self.stream = stream if stream is not None else sys.stdout
        self.metrics = metrics

    def send_batch(
        self, items: Sequence[BatchItem]
    ) -> Tuple[List[BatchItem], List[PoisonItem]]:
        items = list(items)
        for item in items:
            print(item.line, file=self.stream, flush=True)
        if self.metrics is not None and items:
            self.metrics.inc("splunk_delivery_total", len(items))
            self.metrics.set_last("splunk_batch_size", len(items))
        return items, []


class HecClient(Sink):
    """requests.Session-based batched HEC client."""

    def __init__(
        self,
        splunk_config,
        metrics: Metrics,
        logger: Optional[JsonLogger] = None,
        session: Optional[requests.Session] = None,
        sleep_fn=time.sleep,
        clock_fn=time.monotonic,
    ):
        self.config = splunk_config
        self.metrics = metrics
        self.logger = logger or JsonLogger("cloudflow-sink-splunk")
        self.session = session or requests.Session()
        self._sleep = sleep_fn
        self._clock = clock_fn

        token = splunk_config.resolve_token()
        # requests.Session.headers repr never appears in our logs; keep it
        # that way -- the token must never be logged.
        self.session.headers.update({_AUTH_HEADER: f"Splunk {token}"})
        self.session.verify = splunk_config.tls_verify
        if not splunk_config.tls_verify:
            self.logger.warning(
                "TLS verification disabled for Splunk HEC endpoint; this is "
                "insecure and should only be used for local testing",
                hec_url=splunk_config.hec_url,
            )
        self.timeout_s = splunk_config.request_timeout_ms / 1000.0

    def send_batch(
        self, items: Sequence[BatchItem]
    ) -> Tuple[List[BatchItem], List[PoisonItem]]:
        items = list(items)
        if not items:
            return [], []
        return self._send(items, backoff_s=1.0)

    def _post(self, items: Sequence[BatchItem]):
        body = "\n".join(item.line for item in items).encode("utf-8")
        start = self._clock()
        resp = self.session.post(self.config.hec_url, data=body, timeout=self.timeout_s)
        elapsed_ms = (self._clock() - start) * 1000.0
        return resp, elapsed_ms

    def _send(
        self, items: List[BatchItem], backoff_s: float
    ) -> Tuple[List[BatchItem], List[PoisonItem]]:
        while True:
            try:
                resp, elapsed_ms = self._post(items)
            except (requests.Timeout, requests.ConnectionError, requests.RequestException) as exc:
                self.metrics.inc("splunk_retry_total")
                self.logger.warning(
                    "HEC request failed, retrying", error=str(exc), backoff_s=backoff_s
                )
                self._sleep(backoff_s)
                backoff_s = min(backoff_s * 2, 30.0)
                continue

            status = resp.status_code
            if 200 <= status < 300:
                self.metrics.inc("splunk_delivery_total", len(items))
                self.metrics.set_last("splunk_batch_size", len(items))
                self.metrics.record_delivery_latency_ms(elapsed_ms)
                return list(items), []

            if status == 429 or status >= 500:
                self.metrics.inc("splunk_retry_total")
                self.metrics.inc("splunk_delivery_errors_total")
                self.logger.warning(
                    "HEC rejected batch, retrying",
                    status=status,
                    backoff_s=backoff_s,
                    batch_size=len(items),
                )
                self._sleep(backoff_s)
                backoff_s = min(backoff_s * 2, 30.0)
                continue

            # Other 4xx: bisect to isolate the poison event(s).
            self.metrics.inc("splunk_delivery_errors_total")
            body_prefix = (resp.text or "")[:200]
            error = f"HTTP {status}: {body_prefix}"
            if len(items) == 1:
                self.logger.warning(
                    "HEC rejected single event, dead-lettering",
                    status=status,
                    body_prefix=body_prefix,
                )
                return [], [(items[0], error)]

            self.logger.warning(
                "HEC rejected batch with non-retryable status, bisecting",
                status=status,
                batch_size=len(items),
                body_prefix=body_prefix,
            )
            mid = len(items) // 2
            left, right = items[:mid], items[mid:]
            delivered_l, poison_l = self._send(left, backoff_s)
            delivered_r, poison_r = self._send(right, backoff_s)
            return delivered_l + delivered_r, poison_l + poison_r
