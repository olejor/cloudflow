"""Tiny scripted HTTP stub for the WP-17 HEC client CUnit suite.

Usage: hec_stub.py <port> <mode> <reqlog>

Modes:
  5xx_then_2xx   -- first POST returns 503, every subsequent POST returns 200.
  bisect_poison  -- POST returns 400 iff its body contains the token "poison",
                    otherwise 200 (used to exercise batch bisection).

Every request's headers and body are appended to <reqlog> so the C test can
assert the Authorization token was sent on the wire (but never logged by the
client).
"""

import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1])
MODE = sys.argv[2]
REQLOG = sys.argv[3]

_state = {"n": 0}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        with open(REQLOG, "a") as fh:
            fh.write("AUTH:" + str(self.headers.get("Authorization")) + "\n")
            fh.write("BODY:" + body.decode("utf-8", "replace") + "\n")

        if MODE == "5xx_then_2xx":
            _state["n"] += 1
            if _state["n"] == 1:
                status, rb = 503, b"server error"
            else:
                status, rb = 200, b'{"text":"Success","code":0}'
        elif MODE == "bisect_poison":
            if b"poison" in body:
                status, rb = 400, b'{"text":"Invalid event","code":12}'
            else:
                status, rb = 200, b'{"text":"Success","code":0}'
        else:
            status, rb = 200, b"ok"

        self.send_response(status)
        self.send_header("Content-Length", str(len(rb)))
        self.end_headers()
        self.wfile.write(rb)

    def log_message(self, *args):  # silence stderr noise
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
