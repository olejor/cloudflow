"""HEC client retry logic against a stub HTTP server (http.server in a thread).

docs/design/04-sink-splunk.md acceptance criteria:

- 5xx then 2xx -> retried, acked once (delivered exactly once from the
  batcher's point of view);
- 400 on a 3-event batch with one poison -> 2 delivered, 1 dead-lettered
  with reason=hec_rejected, all 3 acked;
- token never appears in logs.

Retry backoff is injected via HecClient(sleep_fn=...) so this suite never
sleeps for real -- it must run in well under a minute.
"""

from __future__ import annotations

import io
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from cloudflow_sink_splunk import config
from cloudflow_sink_splunk.hec import BatchItem, HecClient
from cloudflow_sink_splunk.metrics import JsonLogger, Metrics

TOKEN = "SUPER-SECRET-HEC-TOKEN-DO-NOT-LOG"


def _splunk_config(url, **overrides):
    defaults = dict(
        hec_url=url,
        hec_token_env="TEST_HEC_TOKEN",
        index="",
        sourcetypes={},
        request_timeout_ms=2000,
    )
    defaults.update(overrides)
    return config.SplunkConfig(**defaults)


class _ScriptedHandler(BaseHTTPRequestHandler):
    """Serves a scripted sequence of (status, body) responses in order."""

    responses = []  # class-level, set per-test via server.responses
    requests_seen = []  # list of (headers, body) captured for assertions

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        type(self).requests_seen.append((dict(self.headers.items()), body))
        if type(self).responses:
            status, resp_body = type(self).responses.pop(0)
        else:
            status, resp_body = 200, b'{"text":"Success","code":0}'
        self.send_response(status)
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

    def log_message(self, fmt, *args):  # silence default stderr logging
        pass


@pytest.fixture()
def stub_hec_server():
    _ScriptedHandler.responses = []
    _ScriptedHandler.requests_seen = []
    server = HTTPServer(("127.0.0.1", 0), _ScriptedHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, _ScriptedHandler
    finally:
        server.shutdown()
        thread.join(timeout=5)


def _url(server) -> str:
    host, port = server.server_address
    return f"http://{host}:{port}/services/collector/event"


def _items(n, prefix="e") -> list:
    return [
        BatchItem(stream="cloudflow:v1:wire:dhcpv4", entry_id=f"{i}-0", line=json.dumps({"event": f"{prefix}{i}"}), payload=f"payload-{i}".encode())
        for i in range(n)
    ]


def test_5xx_then_2xx_retries_and_delivers_once(stub_hec_server, monkeypatch):
    server, handler_cls = stub_hec_server
    handler_cls.responses = [(503, b"server error"), (200, b'{"text":"Success","code":0}')]

    monkeypatch.setenv("TEST_HEC_TOKEN", TOKEN)
    splunk_cfg = _splunk_config(_url(server))
    metrics = Metrics("test")
    sleeps = []
    client = HecClient(splunk_cfg, metrics=metrics, sleep_fn=sleeps.append)

    items = _items(2)
    delivered, poison = client.send_batch(items)

    assert [d.entry_id for d in delivered] == [i.entry_id for i in items]
    assert poison == []
    assert len(handler_cls.requests_seen) == 2  # 1 failed + 1 retried
    assert sleeps == [1.0]  # backoff started at 1s, only one retry needed
    assert metrics.snapshot()["splunk_delivery_total"] == 2
    assert metrics.snapshot()["splunk_retry_total"] == 1


def test_backoff_doubles_and_caps_at_30s(stub_hec_server, monkeypatch):
    server, handler_cls = stub_hec_server
    handler_cls.responses = [(503, b"e")] * 6 + [(200, b'{"text":"Success","code":0}')]

    monkeypatch.setenv("TEST_HEC_TOKEN", TOKEN)
    splunk_cfg = _splunk_config(_url(server))
    metrics = Metrics("test")
    sleeps = []
    client = HecClient(splunk_cfg, metrics=metrics, sleep_fn=sleeps.append)

    delivered, poison = client.send_batch(_items(1))

    assert len(delivered) == 1
    assert sleeps == [1.0, 2.0, 4.0, 8.0, 16.0, 30.0]  # doubles then caps at 30


def test_400_on_batch_bisects_isolates_poison_and_delivers_rest(stub_hec_server, monkeypatch):
    server, handler_cls = stub_hec_server

    # 3 items: 400 on the full batch, 400 on the bisected half containing the
    # poison item, 200 for everything else. Order of recursive calls is
    # left-half first then right-half; we script generously so any bisect
    # order that reaches single-item batches succeeds.
    def handler(request_body: bytes):
        lines = request_body.decode().splitlines()
        if any('"poison"' in l for l in lines):
            if len(lines) == 1:
                return 400, b'{"text":"Invalid event","code":12}'
            return 400, b'{"text":"Invalid event","code":12}'
        return 200, b'{"text":"Success","code":0}'

    class DynamicHandler(_ScriptedHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            type(self).requests_seen.append((dict(self.headers.items()), body))
            status, resp_body = handler(body)
            self.send_response(status)
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)

        def log_message(self, fmt, *args):
            pass

    server.RequestHandlerClass = DynamicHandler
    DynamicHandler.requests_seen = []

    monkeypatch.setenv("TEST_HEC_TOKEN", TOKEN)
    splunk_cfg = _splunk_config(_url(server))
    metrics = Metrics("test")
    client = HecClient(splunk_cfg, metrics=metrics, sleep_fn=lambda s: None)

    items = [
        BatchItem(stream="s", entry_id="1-0", line=json.dumps({"event": "ok1"}), payload=b"p1"),
        BatchItem(stream="s", entry_id="2-0", line=json.dumps({"event": "poison"}), payload=b"p2"),
        BatchItem(stream="s", entry_id="3-0", line=json.dumps({"event": "ok3"}), payload=b"p3"),
    ]

    delivered, poison = client.send_batch(items)

    assert {d.entry_id for d in delivered} == {"1-0", "3-0"}
    assert len(poison) == 1
    poison_item, error = poison[0]
    assert poison_item.entry_id == "2-0"
    assert "400" in error


def test_token_never_appears_in_logs(stub_hec_server, monkeypatch):
    server, handler_cls = stub_hec_server
    handler_cls.responses = [(503, b"e"), (200, b'{"text":"Success","code":0}')]

    monkeypatch.setenv("TEST_HEC_TOKEN", TOKEN)
    splunk_cfg = _splunk_config(_url(server))
    metrics = Metrics("test")
    log_stream = io.StringIO()
    logger = JsonLogger("test", stream=log_stream)
    client = HecClient(splunk_cfg, metrics=metrics, logger=logger, sleep_fn=lambda s: None)

    client.send_batch(_items(1))

    log_text = log_stream.getvalue()
    assert TOKEN not in log_text
    # Sanity: the client did actually send the token to the server (so this
    # test would fail if the header stopped being set), just never logged it.
    assert any(
        headers.get("Authorization") == f"Splunk {TOKEN}" for headers, _ in handler_cls.requests_seen
    )


def test_tls_verify_false_logs_loud_warning_without_leaking_token(monkeypatch):
    monkeypatch.setenv("TEST_HEC_TOKEN", TOKEN)
    splunk_cfg = _splunk_config("https://127.0.0.1:1/services/collector/event", tls_verify=False)
    metrics = Metrics("test")
    log_stream = io.StringIO()
    logger = JsonLogger("test", stream=log_stream)

    HecClient(splunk_cfg, metrics=metrics, logger=logger, sleep_fn=lambda s: None)

    log_text = log_stream.getvalue()
    assert "TLS verification disabled" in log_text
    assert TOKEN not in log_text


def test_missing_token_env_raises_config_error(monkeypatch):
    monkeypatch.delenv("TEST_HEC_TOKEN_MISSING", raising=False)
    splunk_cfg = _splunk_config("https://example.com/services/collector/event", hec_token_env="TEST_HEC_TOKEN_MISSING")
    metrics = Metrics("test")
    with pytest.raises(config.ConfigError):
        HecClient(splunk_cfg, metrics=metrics, sleep_fn=lambda s: None)
