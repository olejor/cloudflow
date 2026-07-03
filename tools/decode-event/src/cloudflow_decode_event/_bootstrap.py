"""Locates the two things this tool reuses rather than duplicates:

  cloudflow / cloudflow.v1     generated protobuf bindings (WP-02, mandatory)
  cloudflow_sink_splunk        the Splunk sink package (WP-12, optional --hec)

Both live under sinks/cloudflow-sink-splunk/ in this repo -- that is the
"dependency path" this module declares explicitly:

  sinks/cloudflow-sink-splunk/src/cloudflow_pb/           WP-02 bindings
  sinks/cloudflow-sink-splunk/src/cloudflow_sink_splunk/  WP-12 sink package

Two ways this resolves, matching the pattern already documented in
sinks/cloudflow-sink-splunk/README.md:

1. Installed. `pyproject.toml` declares the protobuf bindings as a real
   packaged dependency (package-dir stitched from the path above, same
   trick sinks/cloudflow-sink-splunk/pyproject.toml uses), so a `pip
   install -e .` of this tool makes `cloudflow.v1` importable with no
   further action. The optional sink package is *not* declared as a
   packaged dependency of this tool (it pulls in `requests`, which
   decode-event otherwise has no use for); install it separately
   (`pip install -e sinks/cloudflow-sink-splunk`) into the same environment
   for --hec to work this way.

2. Dev / no-install. Running straight out of a checkout (`python3 -m
   cloudflow_decode_event ...` with only this tool's own `src/` on
   PYTHONPATH, or even a bare invocation with no PYTHONPATH at all) -- the
   functions below compute the repo root relative to this file's own
   location (the standard cloudflow monorepo layout) and insert the
   missing source directories onto `sys.path` before importing.
"""

from __future__ import annotations

import sys
from pathlib import Path

# This file lives at tools/decode-event/src/cloudflow_decode_event/_bootstrap.py.
# The repo root is four directories up.
_REPO_ROOT = Path(__file__).resolve().parents[4]
_SINK_SRC = _REPO_ROOT / "sinks" / "cloudflow-sink-splunk" / "src"
_PB_ROOT = _SINK_SRC / "cloudflow_pb"


def _ensure_on_syspath(path: Path) -> None:
    text = str(path)
    if path.is_dir() and text not in sys.path:
        sys.path.insert(0, text)


def ensure_protobuf_bindings() -> None:
    """Make ``cloudflow.v1.*_pb2`` importable (WP-02, mandatory)."""
    try:
        import cloudflow.v1.envelope_pb2  # noqa: F401

        return
    except ImportError:
        pass
    _ensure_on_syspath(_PB_ROOT)
    import cloudflow.v1.envelope_pb2  # noqa: F401  -- re-raises ImportError if still missing


def import_sink_transform():
    """Return ``(transform, config)`` modules from ``cloudflow_sink_splunk``
    (WP-12), used only for --hec.

    Raises ImportError with an actionable message if the sink package
    cannot be located either way described in the module docstring.
    """
    try:
        from cloudflow_sink_splunk import config, transform

        return transform, config
    except ImportError:
        pass

    ensure_protobuf_bindings()
    _ensure_on_syspath(_SINK_SRC)
    try:
        from cloudflow_sink_splunk import config, transform

        return transform, config
    except ImportError as exc:
        raise ImportError(
            "cloudflow_sink_splunk (WP-12) is not importable, which --hec "
            "requires. Expected it either pip-installed into this "
            f"environment, or checked out at {_SINK_SRC} (the standard "
            "cloudflow monorepo layout)."
        ) from exc
