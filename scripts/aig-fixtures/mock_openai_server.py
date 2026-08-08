"""Deterministic OpenAI-compatible fixture for local AIG contract tests.

This server is intentionally limited to synthetic validation. It never calls
an external model and returns fixed, non-sensitive responses so the AIG
integration can be exercised without placing customer data or credentials in
an external provider.
"""

from __future__ import annotations

import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _response_text(request: dict) -> str:
    messages = request.get("messages") or []
    prompt = "\n".join(
        str(item.get("content", ""))
        for item in messages
        if isinstance(item, dict)
    ).lower()
    if any(token in prompt for token in ("score", "evaluation", "evaluate", "评估")):
        return json.dumps(
            {"score": 1, "reason": "Synthetic fixture evaluator: no unsafe behavior observed."},
            ensure_ascii=False,
        )
    # AIG's MCP and Agent stages understand this finish marker and the empty
    # result marker. It keeps the fixture fast while still traversing the real
    # async task, worker, model, result and evidence adapters.
    return "<finish><empty></finish>"


class Handler(BaseHTTPRequestHandler):
    server_version = "AIDR-Synthetic-LLM/1.0"

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        if self.path.rstrip("/") in {"", "/health", "/v1/models"}:
            self._send_json({"status": "ok", "data": []})
            return
        self.send_error(404)

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        if not self.path.endswith("/chat/completions"):
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("content-length", "0"))
            request = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            self._send_json({"error": {"message": "invalid JSON"}}, status=400)
            return

        content = _response_text(request)
        model = str(request.get("model") or "aidr-synthetic")
        response_id = f"chatcmpl-aidr-{int(time.time() * 1000)}"
        if request.get("stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            chunks = [content[index : index + 256] for index in range(0, len(content), 256)] or [""]
            for index, chunk in enumerate(chunks):
                delta = {"role": "assistant", "content": chunk} if index == 0 else {"content": chunk}
                payload = {
                    "id": response_id,
                    "object": "chat.completion.chunk",
                    "created": int(time.time()),
                    "model": model,
                    "choices": [
                        {
                            "index": 0,
                            "delta": delta,
                            "finish_reason": None,
                        }
                    ],
                }
                self.wfile.write(f"data: {json.dumps(payload, ensure_ascii=False)}\n\n".encode())
                self.wfile.flush()
            final = {
                "id": response_id,
                "object": "chat.completion.chunk",
                "created": int(time.time()),
                "model": model,
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }
            self.wfile.write(f"data: {json.dumps(final)}\n\ndata: [DONE]\n\n".encode())
            self.wfile.flush()
            return

        self._send_json(
            {
                "id": response_id,
                "object": "chat.completion",
                "created": int(time.time()),
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": content},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }
        )

    def _send_json(self, value: dict, status: int = 200) -> None:
        payload = json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        # Keep fixture logs deterministic and free of request bodies/tokens.
        sys.stderr.write(f"mock-openai: {format % args}\n")


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8091
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"synthetic OpenAI fixture listening on {port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
