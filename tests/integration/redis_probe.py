#!/usr/bin/env python3
"""Minimal, dependency-free Redis RESP client used by
scripts/run-integration-tests.sh (WP-14).

Deliberately stdlib-only (socket only): the sink/source binaries already
depend on hiredis for the real pipeline, but the *test harness* should not
require the optional `redis` PyPI package (it is not one of the promised
project dependencies -- see docs/design/00-overview.md convention 3, Python
deps are protobuf/redis/requests/PyYAML for the *sink*, which is now C; the
test env only promises python3 + the generated `cloudflow_pb` bindings).

Subcommands (all connect to 127.0.0.1:<port> unless --host is given):

  ping                                   -- exit 0 if PONG, else nonzero
  xlen STREAM                            -- print XLEN
  del KEY...                             -- DEL the given keys (best effort)
  pending STREAM GROUP                   -- print XPENDING summary count
  xadd-poison STREAM                     -- XADD a garbage-payload wire entry
                                             (valid schema/encoding/event_type
                                             fields, undecodable payload) --
                                             WP-14 poison-path case
  deadletter-check STREAM REASON ORIGIN  -- assert STREAM has exactly one
                                             entry with reason=REASON and
                                             origin_stream=ORIGIN; print a
                                             one-line summary; exit nonzero
                                             on any mismatch
"""

from __future__ import annotations

import argparse
import socket
import sys


class RedisError(RuntimeError):
    pass


class RespClient:
    def __init__(self, host: str, port: int, timeout: float = 5.0) -> None:
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.buf = b""

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def _fill(self) -> None:
        chunk = self.sock.recv(65536)
        if not chunk:
            raise RedisError("connection closed by redis-server")
        self.buf += chunk

    def _readline(self) -> bytes:
        while b"\r\n" not in self.buf:
            self._fill()
        line, self.buf = self.buf.split(b"\r\n", 1)
        return line

    def _readn(self, n: int) -> bytes:
        while len(self.buf) < n:
            self._fill()
        data, self.buf = self.buf[:n], self.buf[n:]
        return data

    def _read_reply(self):
        line = self._readline()
        kind, rest = line[:1], line[1:]
        if kind == b"+":
            return rest.decode("utf-8", "replace")
        if kind == b"-":
            raise RedisError(rest.decode("utf-8", "replace"))
        if kind == b":":
            return int(rest)
        if kind == b"$":
            n = int(rest)
            if n < 0:
                return None
            data = self._readn(n + 2)[:-2]
            return data
        if kind == b"*":
            n = int(rest)
            if n < 0:
                return None
            return [self._read_reply() for _ in range(n)]
        raise RedisError("unexpected RESP type byte: %r" % kind)

    def cmd(self, *args):
        parts = [b"*%d\r\n" % len(args)]
        for a in args:
            if isinstance(a, str):
                a = a.encode("utf-8")
            elif isinstance(a, int):
                a = str(a).encode("utf-8")
            parts.append(b"$%d\r\n%s\r\n" % (len(a), a))
        self.sock.sendall(b"".join(parts))
        return self._read_reply()


def _decode(v):
    if isinstance(v, bytes):
        return v.decode("utf-8", "replace")
    return v


def cmd_ping(c: RespClient, _args) -> int:
    r = c.cmd("PING")
    if _decode(r) != "PONG":
        print("no PONG reply: %r" % (r,), file=sys.stderr)
        return 1
    return 0


def cmd_xlen(c: RespClient, args) -> int:
    (stream,) = args
    r = c.cmd("XLEN", stream)
    print(r)
    return 0


def cmd_del(c: RespClient, args) -> int:
    if not args:
        print("del: at least one key required", file=sys.stderr)
        return 1
    c.cmd("DEL", *args)
    return 0


def cmd_pending(c: RespClient, args) -> int:
    stream, group = args
    try:
        r = c.cmd("XPENDING", stream, group)
    except RedisError as e:
        # NOGROUP means the consumer group never got created (e.g. the sink
        # never ran) -- that is zero pending by construction.
        if "NOGROUP" in str(e):
            print(0)
            return 0
        raise
    count = r[0] if isinstance(r, list) and r else 0
    print(int(count))
    return 0


def cmd_xadd_poison(c: RespClient, args) -> int:
    (stream,) = args
    entry_id = c.cmd(
        "XADD",
        stream,
        "*",
        "schema",
        "cloudflow.v1.CloudFlowEvent",
        "version",
        "1",
        "encoding",
        "protobuf",
        "event_type",
        "itest.poison.injected",
        "payload",
        b"this-is-not-a-valid-cloudflowevent-protobuf-payload",
    )
    print(_decode(entry_id))
    return 0


def cmd_deadletter_check(c: RespClient, args) -> int:
    stream, expect_reason, expect_origin = args
    entries = c.cmd("XRANGE", stream, "-", "+")
    if not entries:
        print("deadletter-check: stream %s is empty" % stream, file=sys.stderr)
        return 1
    if len(entries) != 1:
        print(
            "deadletter-check: expected exactly 1 entry in %s, found %d"
            % (stream, len(entries)),
            file=sys.stderr,
        )
        return 1
    entry_id, fields = entries[0]
    fmap = {}
    for i in range(0, len(fields) - 1, 2):
        fmap[_decode(fields[i])] = _decode(fields[i + 1])
    ok = True
    if fmap.get("reason") != expect_reason:
        print(
            "deadletter-check: reason=%r, expected %r"
            % (fmap.get("reason"), expect_reason),
            file=sys.stderr,
        )
        ok = False
    if fmap.get("origin_stream") != expect_origin:
        print(
            "deadletter-check: origin_stream=%r, expected %r"
            % (fmap.get("origin_stream"), expect_origin),
            file=sys.stderr,
        )
        ok = False
    if not fmap.get("origin_id"):
        print("deadletter-check: origin_id missing/empty", file=sys.stderr)
        ok = False
    if not ok:
        return 1
    print(
        "OK id=%s reason=%s origin_stream=%s origin_id=%s"
        % (_decode(entry_id), fmap.get("reason"), fmap.get("origin_stream"), fmap.get("origin_id"))
    )
    return 0


SUBCOMMANDS = {
    "ping": (0, cmd_ping),
    "xlen": (1, cmd_xlen),
    "del": (None, cmd_del),
    "pending": (2, cmd_pending),
    "xadd-poison": (1, cmd_xadd_poison),
    "deadletter-check": (3, cmd_deadletter_check),
}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("subcommand", choices=sorted(SUBCOMMANDS))
    parser.add_argument("args", nargs="*")
    ns = parser.parse_args(argv)

    nargs, fn = SUBCOMMANDS[ns.subcommand]
    if nargs is not None and len(ns.args) != nargs:
        parser.error("%s takes exactly %d argument(s)" % (ns.subcommand, nargs))

    try:
        c = RespClient(ns.host, ns.port)
    except OSError as e:
        print("connect failed: %s" % e, file=sys.stderr)
        return 1

    try:
        return fn(c, ns.args)
    except RedisError as e:
        print("redis error: %s" % e, file=sys.stderr)
        return 1
    finally:
        c.close()


if __name__ == "__main__":
    sys.exit(main())
