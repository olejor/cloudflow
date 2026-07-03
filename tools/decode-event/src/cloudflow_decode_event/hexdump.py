"""Hex dump helper for decode-failure diagnostics (docs/building-and-testing.md,
WP-13: "Exit nonzero on decode failure with the protobuf error and a hex
dump of the first 64 bytes.").
"""

from __future__ import annotations

DEFAULT_LIMIT = 64
_BYTES_PER_LINE = 16


def hexdump(data: bytes, limit: int = DEFAULT_LIMIT) -> str:
    chunk = data[:limit]
    lines = []
    for offset in range(0, len(chunk), _BYTES_PER_LINE):
        row = chunk[offset : offset + _BYTES_PER_LINE]
        hex_part = " ".join(f"{b:02x}" for b in row)
        hex_part = f"{hex_part:<{_BYTES_PER_LINE * 3 - 1}}"
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"{offset:08x}  {hex_part}  |{ascii_part}|")
    if not lines:
        lines.append("(empty)")
    suffix = "" if len(data) <= limit else f" ... ({len(data)} bytes total)"
    return "\n".join(lines) + suffix
