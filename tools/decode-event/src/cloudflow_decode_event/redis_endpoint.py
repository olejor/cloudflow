"""Redis endpoint resolution.

Deliberately duplicated in tools/stream-inspect/ rather than factored into a
shared package (docs/building-and-testing.md, WP-13: "a tiny duplicated
helper is acceptable and preferable to a new shared package").

Precedence, per the WP-13 spec:

  1. an explicit ``--redis host:port`` command-line flag
  2. the ``CF_REDIS_ENDPOINTS`` env var (first of a comma-separated list)
  3. ``configs/examples/redis.yaml``, ``redis.endpoints[0]`` (repo-root-relative)
  4. ``localhost:6379``
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Tuple

DEFAULT_HOST = "localhost"
DEFAULT_PORT = 6379

# This file lives at tools/decode-event/src/cloudflow_decode_event/redis_endpoint.py.
# The repo root is four directories up.
_REPO_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_CONFIG_PATH = _REPO_ROOT / "configs" / "examples" / "redis.yaml"


def parse_host_port(value: str, default_port: int = DEFAULT_PORT) -> Tuple[str, int]:
    """Parse a ``host`` or ``host:port`` string."""
    value = value.strip()
    if not value:
        raise ValueError("empty redis endpoint")
    host, sep, port_text = value.rpartition(":")
    if not sep:
        return value, default_port
    host = host or DEFAULT_HOST
    try:
        return host, int(port_text)
    except ValueError as exc:
        raise ValueError(f"invalid redis endpoint {value!r}: bad port") from exc


def _first_endpoint_from_config(config_path: Path) -> Optional[str]:
    if not config_path.is_file():
        return None
    try:
        import yaml

        with open(config_path, "r") as fh:
            raw = yaml.safe_load(fh) or {}
    except Exception:
        # A missing/unreadable/invalid fallback config is not fatal -- the
        # next precedence step (localhost:6379) applies instead.
        return None
    endpoints = ((raw.get("redis") or {}).get("endpoints")) or []
    if endpoints:
        return str(endpoints[0])
    return None


def resolve_redis_endpoint(
    cli_value: Optional[str] = None,
    *,
    env_value: Optional[str] = None,
    config_path: Optional[Path] = None,
) -> Tuple[str, int]:
    """Resolve ``(host, port)`` per the precedence order in the module docstring."""
    if cli_value:
        return parse_host_port(cli_value)

    if env_value is None:
        env_value = os.environ.get("CF_REDIS_ENDPOINTS")
    if env_value:
        first = env_value.split(",")[0].strip()
        if first:
            return parse_host_port(first)

    endpoint = _first_endpoint_from_config(config_path or DEFAULT_CONFIG_PATH)
    if endpoint:
        return parse_host_port(endpoint)

    return DEFAULT_HOST, DEFAULT_PORT
