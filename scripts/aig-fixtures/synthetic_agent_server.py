"""Minimal safe HTTP agent fixture for local Agent-Scan E2E."""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        if self.path != "/chat":
            self.send_error(404)
            return
        length = int(self.headers.get("content-length", "0"))
        _ = self.rfile.read(length)
        payload = json.dumps(
            {"reply": "Synthetic agent refuses secret access and command execution."}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        return


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8092
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
