"""cloudflow-stream-inspect CLI (WP-13, docs/building-and-testing.md).

Default report, for the configured streams (both wire streams + the
dead-letter stream unless ``--stream`` overrides the list): ``XINFO STREAM``
(length, first/last entry id + human time), ``XINFO GROUPS`` (pending count,
last-delivered-id, lag), and consumers with idle times (``XINFO CONSUMERS``).

``--watch``: refreshes a compact one-line-per-stream report every 2s until
interrupted.

``--pending <group>``: lists pending entries for ``<group>`` across the
selected streams, with idle ms and delivery counts (``XPENDING`` detail).

Absent streams/groups are reported as "absent", never a crash.
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime, timezone
from typing import List, Optional, Sequence, TextIO

from .redis_endpoint import resolve_redis_endpoint

# The two wire streams + the sink-splunk dead-letter stream
# (docs/redis-streams.md, configs/examples/redis.yaml).
DEFAULT_STREAMS = [
    "cloudflow:v1:wire:dhcpv4",
    "cloudflow:v1:wire:dhcpv6",
    "cloudflow:v1:deadletter:sink-splunk",
]

WATCH_INTERVAL_S = 2
_PENDING_LIST_COUNT = 1000

EXIT_OK = 0
EXIT_OPERATIONAL = 3


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloudflow-stream-inspect",
        description="Inspect CloudFlow Redis streams and consumer groups.",
    )
    parser.add_argument(
        "--redis",
        help="redis host:port (overrides CF_REDIS_ENDPOINTS / configs/examples/redis.yaml)",
    )
    parser.add_argument(
        "--stream",
        action="append",
        dest="streams",
        metavar="NAME",
        help="stream to inspect (repeatable); default: the two wire streams "
        "plus the sink-splunk dead-letter stream",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="refresh a compact one-line-per-stream report every 2s until Ctrl-C",
    )
    parser.add_argument(
        "--pending",
        metavar="GROUP",
        help="list pending entries (XPENDING detail) for GROUP across the selected streams",
    )
    return parser


def _to_text(value) -> str:
    if value is None:
        return ""
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)


def _entry_id_ms(entry_id) -> Optional[int]:
    text = _to_text(entry_id)
    if not text:
        return None
    ms_part = text.split("-", 1)[0]
    try:
        return int(ms_part)
    except ValueError:
        return None


def _human_time(entry_id) -> str:
    ms = _entry_id_ms(entry_id)
    if ms is None:
        return "?"
    return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _is_missing_key_error(exc) -> bool:
    msg = str(exc)
    return "no such key" in msg.lower() or "NOGROUP" in msg


# -- default report -------------------------------------------------------------


def _print_stream_report(client, stream: str, out: TextIO) -> None:
    import redis

    print(f"== {stream} ==", file=out)
    try:
        info = client.xinfo_stream(stream)
    except redis.exceptions.ResponseError as exc:
        if _is_missing_key_error(exc):
            print("  absent", file=out)
            print(file=out)
            return
        raise

    length = info.get("length")
    first_entry = info.get("first-entry")
    last_entry = info.get("last-entry")
    print(f"  length: {length}", file=out)
    if first_entry:
        fid, _fields = first_entry
        print(f"  first-entry: {_to_text(fid)}  ({_human_time(fid)})", file=out)
    else:
        print("  first-entry: (none)", file=out)
    if last_entry:
        lid, _fields = last_entry
        print(f"  last-entry:  {_to_text(lid)}  ({_human_time(lid)})", file=out)
    else:
        print("  last-entry:  (none)", file=out)

    try:
        groups = client.xinfo_groups(stream)
    except redis.exceptions.ResponseError:
        groups = []

    if not groups:
        print("  groups: (none)", file=out)
    for group in groups:
        gname = _to_text(group.get("name"))
        print(
            f"  group {gname!r}: pending={group.get('pending')} "
            f"last-delivered-id={_to_text(group.get('last-delivered-id'))} "
            f"lag={group.get('lag')}",
            file=out,
        )
        try:
            consumers = client.xinfo_consumers(stream, gname)
        except redis.exceptions.ResponseError:
            consumers = []
        if not consumers:
            print("    consumers: (none)", file=out)
        for consumer in consumers:
            cname = _to_text(consumer.get("name"))
            print(
                f"    consumer {cname!r}: pending={consumer.get('pending')} "
                f"idle_ms={consumer.get('idle')}",
                file=out,
            )
    print(file=out)


def print_full_report(client, streams: Sequence[str], out: Optional[TextIO] = None) -> None:
    out = out if out is not None else sys.stdout
    for stream in streams:
        _print_stream_report(client, stream, out)


# -- --pending <group> ------------------------------------------------------------


def print_pending(client, streams: Sequence[str], group: str, out: Optional[TextIO] = None) -> None:
    import redis

    out = out if out is not None else sys.stdout

    for stream in streams:
        print(f"== {stream} / group {group!r} ==", file=out)
        try:
            entries = client.xpending_range(
                stream, group, min="-", max="+", count=_PENDING_LIST_COUNT
            )
        except redis.exceptions.ResponseError as exc:
            if _is_missing_key_error(exc):
                print("  absent (no such stream or consumer group)", file=out)
                print(file=out)
                continue
            raise
        if not entries:
            print("  (no pending entries)", file=out)
        for item in entries:
            print(
                f"  id={_to_text(item['message_id'])}  "
                f"consumer={_to_text(item['consumer'])}  "
                f"idle_ms={item['time_since_delivered']}  "
                f"delivery_count={item['times_delivered']}",
                file=out,
            )
        print(file=out)


# -- --watch ------------------------------------------------------------------------


def _compact_line(client, stream: str) -> str:
    import redis

    now = datetime.now(timezone.utc).strftime("%H:%M:%S")
    try:
        info = client.xinfo_stream(stream)
    except redis.exceptions.ResponseError as exc:
        if _is_missing_key_error(exc):
            return f"{now}  {stream:<40} absent"
        raise

    length = info.get("length")
    last_id = _to_text(info.get("last-generated-id"))
    try:
        groups = client.xinfo_groups(stream)
    except redis.exceptions.ResponseError:
        groups = []
    total_pending = sum(g.get("pending", 0) or 0 for g in groups)
    total_lag = sum((g.get("lag") or 0) for g in groups)
    return (
        f"{now}  {stream:<40} len={length:<8} groups={len(groups):<3} "
        f"pending={total_pending:<6} lag={total_lag:<6} last_id={last_id}"
    )


def watch(
    client,
    streams: Sequence[str],
    *,
    out: Optional[TextIO] = None,
    sleep_fn=time.sleep,
    max_iterations: Optional[int] = None,
) -> None:
    out = out if out is not None else sys.stdout
    iterations = 0
    try:
        while max_iterations is None or iterations < max_iterations:
            for stream in streams:
                print(_compact_line(client, stream), file=out)
            iterations += 1
            if max_iterations is None or iterations < max_iterations:
                sleep_fn(WATCH_INTERVAL_S)
    except KeyboardInterrupt:
        pass


# -- entry point ------------------------------------------------------------------------


def run(
    argv: Optional[Sequence[str]] = None,
    *,
    out: Optional[TextIO] = None,
    sleep_fn=time.sleep,
    max_watch_iterations: Optional[int] = None,
) -> int:
    import redis

    out = out if out is not None else sys.stdout
    args = build_arg_parser().parse_args(argv)
    streams: List[str] = args.streams or list(DEFAULT_STREAMS)

    host, port = resolve_redis_endpoint(args.redis)
    client = redis.Redis(host=host, port=port, decode_responses=False)
    try:
        client.ping()
    except redis.exceptions.RedisError as exc:
        sys.stderr.write(f"error: cannot connect to redis at {host}:{port}: {exc}\n")
        return EXIT_OPERATIONAL

    if args.pending:
        print_pending(client, streams, args.pending, out=out)
        return EXIT_OK

    if args.watch:
        watch(client, streams, out=out, sleep_fn=sleep_fn, max_iterations=max_watch_iterations)
        return EXIT_OK

    print_full_report(client, streams, out=out)
    return EXIT_OK


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
