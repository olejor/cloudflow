"""cloudflow-decode-event CLI (WP-13, docs/design/05-tools-tests-ci.md).

Input modes (exactly one):

  --stream <name> --id <entry-id>   fetch one entry via XRANGE
  --stream <name> --last N          fetch the N most recent entries via XREVRANGE
  --file <path>                     raw packed CloudFlowEvent bytes
  (no input flags at all)           read raw packed CloudFlowEvent bytes from stdin

Output: pretty-printed JSON via the same
``google.protobuf.json_format.MessageToDict(preserving_proto_field_name=True)``
rule WP-12 uses. ``--hec`` prints the full canonical HEC mapping
(docs/design/04-sink-splunk.md) instead, by importing and calling the sink's
own ``transform.render_hec_line`` (see ``_bootstrap.py`` -- the mapping is
reused, never duplicated).

Decode failure: nonzero exit, the protobuf error and a hex dump of the first
64 bytes on stderr, nothing decodable on stdout.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional, Sequence, Tuple

from . import _bootstrap
from .hexdump import hexdump
from .redis_endpoint import resolve_redis_endpoint

EXIT_OK = 0
EXIT_DECODE_FAILURE = 1
EXIT_ARGS = 2
EXIT_OPERATIONAL = 3


class CliError(Exception):
    """An operational or argument error -- distinct from a decode failure."""


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloudflow-decode-event",
        description="Decode a packed CloudFlowEvent and print it as JSON, "
        "or as the canonical WP-12 Splunk HEC mapping with --hec.",
    )
    parser.add_argument("--stream", help="Redis stream name to fetch the entry/entries from")
    parser.add_argument("--id", help="entry id to fetch (XRANGE); requires --stream")
    parser.add_argument(
        "--last",
        type=int,
        metavar="N",
        help="fetch the N most recent entries (XREVRANGE); requires --stream",
    )
    parser.add_argument("--file", help="path to a file containing raw packed CloudFlowEvent bytes")
    parser.add_argument(
        "--hec",
        action="store_true",
        help="print the canonical WP-12 Splunk HEC mapping instead of raw decoded JSON",
    )
    parser.add_argument(
        "--redis",
        help="redis host:port (overrides CF_REDIS_ENDPOINTS / configs/examples/redis.yaml)",
    )
    return parser


def _validate_args(args: argparse.Namespace) -> None:
    if args.file and (args.stream or args.id is not None or args.last is not None):
        raise CliError("--file cannot be combined with --stream/--id/--last")
    if args.id is not None and args.last is not None:
        raise CliError("--id and --last are mutually exclusive")
    if (args.id is not None or args.last is not None) and not args.stream:
        raise CliError("--id/--last require --stream")
    if args.stream and args.id is None and args.last is None:
        raise CliError("--stream requires --id or --last")
    if args.last is not None and args.last <= 0:
        raise CliError("--last must be a positive integer")


def _to_text(value) -> str:
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else value


def _entries_from_stream(args: argparse.Namespace) -> List[Tuple[str, bytes]]:
    import redis

    host, port = resolve_redis_endpoint(args.redis)
    client = redis.Redis(host=host, port=port, decode_responses=False)
    try:
        client.ping()
    except redis.exceptions.RedisError as exc:
        raise CliError(f"cannot connect to redis at {host}:{port}: {exc}") from exc

    if args.id is not None:
        try:
            entries = client.xrange(args.stream, min=args.id, max=args.id, count=1)
        except redis.exceptions.ResponseError as exc:
            raise CliError(f"XRANGE {args.stream} {args.id}: {exc}") from exc
        if not entries:
            raise CliError(f"no entry {args.id!r} in stream {args.stream!r}")
    else:
        try:
            entries = client.xrevrange(args.stream, count=args.last)
        except redis.exceptions.ResponseError as exc:
            raise CliError(f"XREVRANGE {args.stream}: {exc}") from exc
        if not entries:
            raise CliError(f"stream {args.stream!r} is empty or does not exist")

    result: List[Tuple[str, bytes]] = []
    for entry_id, fields in entries:
        payload = fields.get(b"payload")
        label = f"{args.stream}:{_to_text(entry_id)}"
        if payload is None:
            raise CliError(f"entry {label} has no 'payload' field")
        result.append((label, payload))
    return result


def _read_input_bytes(args: argparse.Namespace) -> List[Tuple[str, bytes]]:
    """Returns [(label, raw_bytes), ...] to decode, in display order."""
    if args.file:
        try:
            with open(args.file, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            raise CliError(f"cannot read {args.file!r}: {exc}") from exc
        return [(args.file, data)]

    if args.stream:
        return _entries_from_stream(args)

    data = sys.stdin.buffer.read()
    return [("<stdin>", data)]


def _default_splunk_config():
    """The SplunkConfig used for --hec: no operator config file exists for
    this debug tool, so this uses the mapping's defaults exactly
    (docs/design/04-sink-splunk.md): no index, no sourcetype overrides
    (falls back to ``cloudflow:<source_type>``), raw DHCP payload stripped.
    """
    from . import hec_mapping

    return hec_mapping.SplunkConfig()


def _decode_one(label: str, data: bytes, *, hec: bool, stream_name: Optional[str]) -> bool:
    """Decode and print one event. Returns True on success."""
    from google.protobuf import message as message_mod

    _bootstrap.ensure_protobuf_bindings()
    from cloudflow.v1.envelope_pb2 import CloudFlowEvent

    event = CloudFlowEvent()
    try:
        event.ParseFromString(data)
    except message_mod.DecodeError as exc:
        sys.stderr.write(f"decode error for {label}: {exc}\n")
        sys.stderr.write(hexdump(data) + "\n")
        return False

    if hec:
        from . import hec_mapping

        splunk_cfg = _default_splunk_config()
        effective_stream = stream_name or event.envelope.stream_name or ""
        print(hec_mapping.render_hec_line(event, effective_stream, splunk_cfg))
    else:
        from google.protobuf import json_format

        as_dict = json_format.MessageToDict(event, preserving_proto_field_name=True)
        print(json.dumps(as_dict, indent=2, sort_keys=True))
    return True


def run(argv: Optional[Sequence[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    try:
        _validate_args(args)
    except CliError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return EXIT_ARGS

    try:
        items = _read_input_bytes(args)
    except CliError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return EXIT_OPERATIONAL

    stream_name = args.stream or None
    multi = len(items) > 1
    all_ok = True
    for label, data in items:
        if multi:
            print(f"=== {label} ===")
        ok = _decode_one(label, data, hec=args.hec, stream_name=stream_name)
        all_ok = all_ok and ok

    return EXIT_OK if all_ok else EXIT_DECODE_FAILURE


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
