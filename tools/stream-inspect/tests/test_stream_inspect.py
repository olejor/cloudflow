"""pytest coverage for cloudflow-stream-inspect (docs/design/05-tools-tests-ci.md,
WP-13 acceptance criteria): against a private redis-server, populate a
stream + group, assert the report shows it and pending goes to 0 after ack,
and the --pending listing shows a pending entry's delivery count. Also
covers absent streams/groups being reported gracefully (never a crash) and
basic argument handling.
"""

from __future__ import annotations

from cloudflow_stream_inspect import cli

STREAM = "cloudflow:v1:wire:dhcpv4"
OTHER_STREAM = "cloudflow:v1:wire:dhcpv6"
GROUP = "sink-splunk"


def _redis_arg(redis_server) -> str:
    return f"{redis_server['host']}:{redis_server['port']}"


def test_report_shows_populated_stream_and_group(redis_server, redis_client, capsys):
    redis_client.xadd(STREAM, {"payload": b"one"})
    redis_client.xadd(STREAM, {"payload": b"two"})
    redis_client.xgroup_create(STREAM, GROUP, id="0")
    redis_client.xreadgroup(GROUP, "consumer-1", {STREAM: ">"}, count=10)

    exit_code = cli.run(["--redis", _redis_arg(redis_server), "--stream", STREAM])
    out = capsys.readouterr().out

    assert exit_code == cli.EXIT_OK
    assert f"== {STREAM} ==" in out
    assert "length: 2" in out
    assert f"group {GROUP!r}" in out
    assert "pending=2" in out
    assert "consumer 'consumer-1'" in out


def test_pending_goes_to_zero_after_ack(redis_server, redis_client, capsys):
    entry_id = redis_client.xadd(STREAM, {"payload": b"one"})
    redis_client.xgroup_create(STREAM, GROUP, id="0")
    redis_client.xreadgroup(GROUP, "consumer-1", {STREAM: ">"}, count=10)

    exit_code = cli.run(["--redis", _redis_arg(redis_server), "--stream", STREAM])
    out_before = capsys.readouterr().out
    assert exit_code == cli.EXIT_OK
    assert "pending=1" in out_before

    redis_client.xack(STREAM, GROUP, entry_id)

    exit_code = cli.run(["--redis", _redis_arg(redis_server), "--stream", STREAM])
    out_after = capsys.readouterr().out
    assert exit_code == cli.EXIT_OK
    assert "pending=0" in out_after
    assert "pending=1" not in out_after


def test_pending_listing_shows_delivery_count(redis_server, redis_client, capsys):
    entry_id = redis_client.xadd(STREAM, {"payload": b"one"})
    redis_client.xgroup_create(STREAM, GROUP, id="0")
    redis_client.xreadgroup(GROUP, "consumer-1", {STREAM: ">"}, count=10)
    # Force a second delivery (XCLAIM) so times_delivered goes from 1 to 2 --
    # this is exactly the "stuck consumer" case --pending exists for.
    redis_client.xclaim(STREAM, GROUP, "consumer-2", min_idle_time=0, message_ids=[entry_id])

    exit_code = cli.run(
        ["--redis", _redis_arg(redis_server), "--stream", STREAM, "--pending", GROUP]
    )
    out = capsys.readouterr().out

    assert exit_code == cli.EXIT_OK
    assert entry_id.decode() in out
    assert "consumer=consumer-2" in out
    assert "delivery_count=2" in out


def test_pending_with_no_pending_entries(redis_server, redis_client, capsys):
    redis_client.xadd(STREAM, {"payload": b"one"})
    redis_client.xgroup_create(STREAM, GROUP, id="$")  # group starts at the tail: nothing pending

    exit_code = cli.run(
        ["--redis", _redis_arg(redis_server), "--stream", STREAM, "--pending", GROUP]
    )
    out = capsys.readouterr().out

    assert exit_code == cli.EXIT_OK
    assert "(no pending entries)" in out


def test_absent_stream_is_reported_not_crashed(redis_server, capsys):
    exit_code = cli.run(
        ["--redis", _redis_arg(redis_server), "--stream", "cloudflow:v1:wire:does-not-exist"]
    )
    out = capsys.readouterr().out

    assert exit_code == cli.EXIT_OK
    assert "absent" in out


def test_absent_group_in_pending_mode_is_reported_not_crashed(redis_server, redis_client, capsys):
    redis_client.xadd(STREAM, {"payload": b"one"})

    exit_code = cli.run(
        ["--redis", _redis_arg(redis_server), "--stream", STREAM, "--pending", "no-such-group"]
    )
    out = capsys.readouterr().out

    assert exit_code == cli.EXIT_OK
    assert "absent" in out


def test_default_streams_are_the_three_configured_streams(redis_server, capsys):
    exit_code = cli.run(["--redis", _redis_arg(redis_server)])
    out = capsys.readouterr().out

    assert exit_code == cli.EXIT_OK
    for stream in cli.DEFAULT_STREAMS:
        assert f"== {stream} ==" in out


def test_multiple_streams_all_reported(redis_server, redis_client, capsys):
    redis_client.xadd(STREAM, {"payload": b"one"})
    redis_client.xadd(OTHER_STREAM, {"payload": b"two"})

    exit_code = cli.run(
        ["--redis", _redis_arg(redis_server), "--stream", STREAM, "--stream", OTHER_STREAM]
    )
    out = capsys.readouterr().out

    assert exit_code == cli.EXIT_OK
    assert f"== {STREAM} ==" in out
    assert f"== {OTHER_STREAM} ==" in out


def test_watch_mode_prints_one_compact_line_per_stream_per_iteration(redis_server, redis_client, capsys):
    redis_client.xadd(STREAM, {"payload": b"one"})

    sleeps = []
    exit_code = cli.run(
        ["--redis", _redis_arg(redis_server), "--stream", STREAM],
    )
    capsys.readouterr()  # discard the default-report baseline output above

    exit_code = cli.run(
        ["--redis", _redis_arg(redis_server), "--stream", STREAM, "--watch"],
        sleep_fn=sleeps.append,
        max_watch_iterations=3,
    )
    out = capsys.readouterr().out
    lines = [l for l in out.splitlines() if l.strip()]

    assert exit_code == cli.EXIT_OK
    assert len(lines) == 3  # one compact line per iteration (one stream selected)
    assert all(STREAM in l and "len=" in l for l in lines)
    assert sleeps == [2, 2]  # slept between iterations 1->2 and 2->3, not after the last


def test_connection_failure_is_operational_error(capsys):
    exit_code = cli.run(["--redis", "127.0.0.1:1"])  # nothing listening
    captured = capsys.readouterr()

    assert exit_code == cli.EXIT_OPERATIONAL
    assert "cannot connect" in captured.err
