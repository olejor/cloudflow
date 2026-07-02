"""YAML configuration loading for cloudflow-sink-splunk.

Schema matches ``configs/examples/splunk-sink.yaml`` (decision D6): endpoints
and topology come from YAML, secrets come from the environment only. See
``docs/design/04-sink-splunk.md`` for the authoritative schema description.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import yaml

# Defaults mirror configs/examples/splunk-sink.yaml so an operator's YAML can
# omit any of these and still get the documented example behavior.
DEFAULT_CONSUMER_GROUP = "sink-splunk"
DEFAULT_READ_COUNT = 100
DEFAULT_BLOCK_MS = 1000
DEFAULT_BATCH_SIZE = 500
DEFAULT_FLUSH_INTERVAL_MS = 1000
DEFAULT_REQUEST_TIMEOUT_MS = 5000
DEFAULT_TLS_VERIFY = True
DEFAULT_INCLUDE_RAW_PAYLOAD = False

# A real environment variable *name* looks like FOO or FOO_BAR. HEC tokens
# (GUIDs, 64-char hex strings, "Splunk <uuid>" strings...) do not. If
# splunk.hec_token_env fails this, someone probably pasted a literal token
# into YAML by mistake -- decision D6 requires secrets to be env-only.
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


class ConfigError(Exception):
    """Raised for any problem loading or validating the sink configuration."""


@dataclass
class ServiceConfig:
    name: str
    consumer_name: str


@dataclass
class RedisConfig:
    endpoints: List[str]
    streams: List[str]
    consumer_group: str = DEFAULT_CONSUMER_GROUP
    read_count: int = DEFAULT_READ_COUNT
    block_ms: int = DEFAULT_BLOCK_MS


@dataclass
class SplunkConfig:
    hec_url: str
    hec_token_env: str
    index: str = ""
    sourcetypes: Dict[str, str] = field(default_factory=dict)
    batch_size: int = DEFAULT_BATCH_SIZE
    flush_interval_ms: int = DEFAULT_FLUSH_INTERVAL_MS
    request_timeout_ms: int = DEFAULT_REQUEST_TIMEOUT_MS
    tls_verify: bool = DEFAULT_TLS_VERIFY
    include_raw_payload: bool = DEFAULT_INCLUDE_RAW_PAYLOAD

    def sourcetype_for(self, source_type: str) -> str:
        configured = self.sourcetypes.get(source_type)
        if configured:
            return configured
        return f"cloudflow:{source_type}"

    def resolve_token(self) -> str:
        """Fetch the HEC token from the environment. Never from YAML."""
        token = os.environ.get(self.hec_token_env)
        if not token:
            raise ConfigError(
                f"HEC token env var {self.hec_token_env!r} (from splunk.hec_token_env) "
                "is not set or empty"
            )
        return token


@dataclass
class Config:
    service: ServiceConfig
    redis: RedisConfig
    splunk: SplunkConfig


def _require(mapping: dict, key: str, section: str):
    if key not in mapping or mapping[key] in (None, ""):
        raise ConfigError(f"{section}.{key} is required")
    return mapping[key]


def _check_no_literal_token(splunk_raw: dict) -> None:
    for forbidden in ("hec_token", "token", "hec_secret", "secret"):
        if forbidden in splunk_raw:
            raise ConfigError(
                f"splunk.{forbidden} must not appear in YAML; the HEC token is "
                "read only from the environment variable named by "
                "splunk.hec_token_env (decision D6)"
            )


def _check_env_name_looks_like_env_name(hec_token_env: str) -> None:
    if not isinstance(hec_token_env, str) or not _ENV_NAME_RE.match(hec_token_env):
        raise ConfigError(
            f"splunk.hec_token_env={hec_token_env!r} does not look like an "
            "environment variable name -- it looks like a literal secret was "
            "pasted into YAML, which is a startup error (decision D6)"
        )


def _parse_service(raw: dict) -> ServiceConfig:
    raw = raw or {}
    return ServiceConfig(
        name=_require(raw, "name", "service"),
        consumer_name=_require(raw, "consumer_name", "service"),
    )


def _parse_redis(raw: dict) -> RedisConfig:
    raw = raw or {}
    endpoints = _require(raw, "endpoints", "redis")
    if not isinstance(endpoints, list) or not endpoints:
        raise ConfigError("redis.endpoints must be a non-empty list")
    streams = _require(raw, "streams", "redis")
    if not isinstance(streams, list) or not streams:
        raise ConfigError("redis.streams must be a non-empty list")
    return RedisConfig(
        endpoints=list(endpoints),
        streams=list(streams),
        consumer_group=raw.get("consumer_group", DEFAULT_CONSUMER_GROUP),
        read_count=int(raw.get("read_count", DEFAULT_READ_COUNT)),
        block_ms=int(raw.get("block_ms", DEFAULT_BLOCK_MS)),
    )


def _parse_splunk(raw: dict) -> SplunkConfig:
    raw = raw or {}
    _check_no_literal_token(raw)
    hec_url = _require(raw, "hec_url", "splunk")
    hec_token_env = _require(raw, "hec_token_env", "splunk")
    _check_env_name_looks_like_env_name(hec_token_env)
    sourcetypes = raw.get("sourcetypes", {}) or {}
    if not isinstance(sourcetypes, dict):
        raise ConfigError("splunk.sourcetypes must be a mapping")
    return SplunkConfig(
        hec_url=hec_url,
        hec_token_env=hec_token_env,
        index=raw.get("index", "") or "",
        sourcetypes=dict(sourcetypes),
        batch_size=int(raw.get("batch_size", DEFAULT_BATCH_SIZE)),
        flush_interval_ms=int(raw.get("flush_interval_ms", DEFAULT_FLUSH_INTERVAL_MS)),
        request_timeout_ms=int(raw.get("request_timeout_ms", DEFAULT_REQUEST_TIMEOUT_MS)),
        tls_verify=bool(raw.get("tls_verify", DEFAULT_TLS_VERIFY)),
        include_raw_payload=bool(raw.get("include_raw_payload", DEFAULT_INCLUDE_RAW_PAYLOAD)),
    )


def parse(raw: dict) -> Config:
    if not isinstance(raw, dict):
        raise ConfigError("top-level config must be a mapping")
    return Config(
        service=_parse_service(raw.get("service")),
        redis=_parse_redis(raw.get("redis")),
        splunk=_parse_splunk(raw.get("splunk")),
    )


def load(path: str) -> Config:
    try:
        with open(path, "r") as fh:
            raw = yaml.safe_load(fh)
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path!r}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path!r}: {exc}") from exc
    return parse(raw or {})
