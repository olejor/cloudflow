"""Shared pytest fixtures for cloudflow-stream-inspect tests.

Mirrors sinks/cloudflow-sink-splunk/tests/conftest.py's sys.path bootstrap
(same monorepo layout, so a bare `pytest` invocation from this directory
works without `pip install -e .` first) and its private, throwaway
redis-server fixture pattern (skips cleanly when redis-server is
unavailable).
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = _HERE.parent  # tools/stream-inspect

for _p in (_PKG_ROOT / "src",):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def redis_server():
    """Start a private, throwaway redis-server for the test session.

    Skips (does not fail) any test that uses it if redis-server cannot be
    found or started.
    """
    redis_server_bin = shutil.which("redis-server")
    if not redis_server_bin:
        pytest.skip("redis-server not found on PATH")

    port = _free_port()
    proc = subprocess.Popen(
        [
            redis_server_bin,
            "--port",
            str(port),
            "--save",
            "",
            "--appendonly",
            "no",
            "--daemonize",
            "no",
            "--bind",
            "127.0.0.1",
            "--protected-mode",
            "no",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        import redis as redis_lib

        client = redis_lib.Redis(host="127.0.0.1", port=port)
        deadline = time.monotonic() + 10
        last_exc = None
        while time.monotonic() < deadline:
            try:
                if client.ping():
                    break
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                if proc.poll() is not None:
                    pytest.skip(f"redis-server exited before becoming ready: {last_exc}")
                time.sleep(0.1)
        else:
            proc.terminate()
            pytest.skip(f"redis-server did not become ready in time: {last_exc}")

        yield {"host": "127.0.0.1", "port": port}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


@pytest.fixture()
def redis_client(redis_server):
    import redis as redis_lib

    client = redis_lib.Redis(host=redis_server["host"], port=redis_server["port"], decode_responses=False)
    client.flushall()
    yield client
    client.flushall()
    client.close()
