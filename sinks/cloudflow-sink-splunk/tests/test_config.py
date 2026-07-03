"""config.py: schema loading, env-only token, and startup-error validation."""

from __future__ import annotations

import textwrap

import pytest

from cloudflow_sink_splunk import config

BASE_YAML = """
service:
  name: cloudflow-sink-splunk
  consumer_name: splunk-01

redis:
  endpoints:
    - redis01:6379
  streams:
    - cloudflow:v1:wire:dhcpv4
    - cloudflow:v1:wire:dhcpv6

splunk:
  hec_url: https://splunk.example.com:8088/services/collector/event
  hec_token_env: SPLUNK_HEC_TOKEN
"""


def _load(yaml_text, tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(textwrap.dedent(yaml_text))
    return config.load(str(path))


def test_defaults_match_example(tmp_path):
    cfg = _load(BASE_YAML, tmp_path)
    assert cfg.redis.consumer_group == "sink-splunk"
    assert cfg.redis.read_count == 100
    assert cfg.redis.block_ms == 1000
    assert cfg.splunk.batch_size == 500
    assert cfg.splunk.flush_interval_ms == 1000
    assert cfg.splunk.request_timeout_ms == 5000
    assert cfg.splunk.tls_verify is True
    assert cfg.splunk.include_raw_payload is False
    assert cfg.splunk.index == ""


def test_full_example_matches_configs_examples_splunk_sink_yaml(tmp_path):
    full = """
    service:
      name: cloudflow-sink-splunk
      consumer_name: splunk-01

    redis:
      endpoints:
        - redis01:6379
        - redis02:6379
        - redis03:6379
      streams:
        - cloudflow:v1:wire:dhcpv4
        - cloudflow:v1:wire:dhcpv6
      consumer_group: sink-splunk
      read_count: 100
      block_ms: 1000

    splunk:
      hec_url: https://splunk.example.com:8088/services/collector/event
      hec_token_env: SPLUNK_HEC_TOKEN
      index: network
      sourcetypes:
        dhcpv4: cloudflow:dhcpv4
        dhcpv6: cloudflow:dhcpv6
      batch_size: 500
      flush_interval_ms: 1000
      request_timeout_ms: 5000
    """
    cfg = _load(full, tmp_path)
    assert cfg.service.name == "cloudflow-sink-splunk"
    assert cfg.service.consumer_name == "splunk-01"
    assert cfg.redis.endpoints == ["redis01:6379", "redis02:6379", "redis03:6379"]
    assert cfg.redis.streams == ["cloudflow:v1:wire:dhcpv4", "cloudflow:v1:wire:dhcpv6"]
    assert cfg.splunk.index == "network"
    assert cfg.splunk.sourcetype_for("dhcpv4") == "cloudflow:dhcpv4"
    assert cfg.splunk.sourcetype_for("unknown") == "cloudflow:unknown"


def test_token_looking_string_in_hec_token_env_is_startup_error(tmp_path):
    bad = BASE_YAML.replace(
        "hec_token_env: SPLUNK_HEC_TOKEN",
        "hec_token_env: 8f14e45fceea167a5a36dedd4bea2543-not-an-env-var-name",
    )
    with pytest.raises(config.ConfigError):
        _load(bad, tmp_path)


def test_literal_hec_token_key_in_yaml_is_startup_error(tmp_path):
    bad = BASE_YAML + "  hec_token: 8f14e45fceea167a5a36dedd4bea2543\n"
    with pytest.raises(config.ConfigError):
        _load(bad, tmp_path)


def test_token_comes_only_from_env(tmp_path, monkeypatch):
    cfg = _load(BASE_YAML, tmp_path)
    monkeypatch.delenv("SPLUNK_HEC_TOKEN", raising=False)
    with pytest.raises(config.ConfigError):
        cfg.splunk.resolve_token()

    monkeypatch.setenv("SPLUNK_HEC_TOKEN", "abc123")
    assert cfg.splunk.resolve_token() == "abc123"


@pytest.mark.parametrize("missing_section", ["service", "redis", "splunk"])
def test_missing_required_section_is_startup_error(tmp_path, missing_section):
    import yaml as pyyaml

    raw = pyyaml.safe_load(BASE_YAML)
    raw.pop(missing_section)
    path = tmp_path / "config.yaml"
    path.write_text(pyyaml.safe_dump(raw))
    with pytest.raises(config.ConfigError):
        config.load(str(path))
