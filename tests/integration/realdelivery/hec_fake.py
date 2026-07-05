#!/usr/bin/env python3
"""Minimal fake Splunk HEC receiver for the real-delivery integration harness.

It stands in for Splunk so the Splunk event and metrics sinks exercise their
*real* HTTP delivery path (libcurl POST, batching, retry, ack-after-2xx,
dead-letter) instead of the --stdout shortcut. It:

  * accepts POST to any path under /services/collector (the event sink posts to
    /services/collector/event, the metrics sink to /services/collector),
  * parses the body as one-or-more concatenated JSON objects (HEC batches this
    way, not as a JSON array),
  * appends every received object -- tagged with the request path -- as one
    JSON line to CF_HEC_RECORD so run.sh can assert what actually arrived,
  * returns the HEC success envelope {"text":"Success","code":0} with 200,
  * optionally fails the first CF_HEC_FAIL_TIMES requests with
    CF_HEC_FAIL_STATUS (default 503) to exercise the sinks' retry path,
  * answers GET /health with 200 for compose healthchecks.

Standard library only -- no build step, runs anywhere python3 is present.
Configuration is entirely via environment (never the command line), matching
the project's secrets-in-env stance.
"""

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RECORD_PATH = os.environ.get("CF_HEC_RECORD", "/work/hec_received.jsonl")
LISTEN_PORT = int(os.environ.get("CF_HEC_PORT", "8088"))
FAIL_TIMES = int(os.environ.get("CF_HEC_FAIL_TIMES", "0"))
FAIL_STATUS = int(os.environ.get("CF_HEC_FAIL_STATUS", "503"))

_lock = threading.Lock()
_fail_remaining = FAIL_TIMES


def _split_json_objects(body):
    """Yield each top-level JSON object from a HEC body of concatenated
    objects (optionally separated by whitespace/newlines)."""
    decoder = json.JSONDecoder()
    idx = 0
    n = len(body)
    while idx < n:
        while idx < n and body[idx] in " \t\r\n":
            idx += 1
        if idx >= n:
            break
        obj, end = decoder.raw_decode(body, idx)
        yield obj
        idx = end


class Handler(BaseHTTPRequestHandler):
    # Quieter, structured-ish logging to stderr.
    def log_message(self, fmt, *args):
        sys.stderr.write("[hec-fake] " + (fmt % args) + "\n")

    def do_GET(self):
        if self.path.startswith("/health"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        global _fail_remaining

        if not self.path.startswith("/services/collector"):
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8", "replace")

        # Fail-injection: burn the first N requests to exercise sink retry.
        with _lock:
            if _fail_remaining > 0:
                _fail_remaining -= 1
                self.log_message("injected failure %d (%d left)", FAIL_STATUS, _fail_remaining)
                self.send_response(FAIL_STATUS)
                self.end_headers()
                self.wfile.write(b'{"text":"injected failure","code":8}')
                return

        try:
            objs = list(_split_json_objects(raw))
        except ValueError as exc:
            self.log_message("unparseable body: %s", exc)
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"text":"invalid data format","code":6}')
            return

        with _lock:
            with open(RECORD_PATH, "a", encoding="utf-8") as fh:
                for obj in objs:
                    fh.write(json.dumps({"path": self.path, "event": obj}) + "\n")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"text":"Success","code":0}')


def main():
    # Truncate the record file at startup so each harness run is clean.
    open(RECORD_PATH, "w", encoding="utf-8").close()
    server = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler)
    sys.stderr.write(
        "[hec-fake] listening on :%d, recording to %s (fail_times=%d)\n"
        % (LISTEN_PORT, RECORD_PATH, FAIL_TIMES)
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
