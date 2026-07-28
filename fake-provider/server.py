#!/usr/bin/env python3
"""A deterministic fake Provider for the dev stack and milestone checks.

It speaks just enough of the OpenAI Responses wire format for Hamza's Adapter to
parse a Turn: a small SSE stream ending in `response.completed` with a `usage`
block whose token math satisfies the invariants
(cached <= input, reasoning <= output, total = input + output).

No external dependencies — Python stdlib only — so it runs in `python:3.12-slim`
with no build step.
"""
import json
import os
import sys
import threading
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timezone

# Deterministic usage. Invariants: cached(20) <= input(120);
# reasoning(30) <= output(80); total(200) = input(120) + output(80).
USAGE = {
    "input_tokens": 120,
    "input_tokens_details": {"cached_tokens": 20},
    "output_tokens": 80,
    "output_tokens_details": {"reasoning_tokens": 30},
    "total_tokens": 200,
}

FLOW_FEED_PATH = os.environ.get("HAMZA_FLOW_FEED_PATH", "")
FLOW_FQDN_OPENAI = os.environ.get("HAMZA_FLOW_FEED_OPENAI_FQDN", "api.openai.com")
FLOW_FQDN_ANTHROPIC = os.environ.get("HAMZA_FLOW_FEED_ANTHROPIC_FQDN", "api.anthropic.com")
FLOW_LOCK = threading.Lock()
EVENT_PATH = os.environ.get("HAMZA_PROVIDER_EVENT_PATH", "")
EXPECTED_AUTH = os.environ.get("HAMZA_PROVIDER_EXPECTED_AUTH", "")
EXPECTED_X_API_KEY = os.environ.get("HAMZA_PROVIDER_EXPECTED_X_API_KEY", "")
PROTECTED_VALUES = tuple(
    value.encode("utf-8")
    for value in os.environ.get("HAMZA_PROVIDER_PROTECTED_VALUES", "").split("|")
    if value
)
# The bounded Placeholder families a masked DERIVED body may carry.
MASK_PLACEHOLDER = re.compile(
    rb"<(?:SECRET|ACCOUNT|EMAIL|PHONE|PERSON|LOCATION|IP|PII)_[0-9]+>")
EVENT_LOCK = threading.Lock()
PLACEHOLDER_CLASSES = {}
EVENT_SEQUENCE = 0


def _log(msg):
    print(f"[fake-provider] {msg}", flush=True)


def _flow_destination(path):
    return FLOW_FQDN_ANTHROPIC if "/v1/messages" in path else FLOW_FQDN_OPENAI


def _write_flow_event(path, byte_count):
    if not FLOW_FEED_PATH:
        return
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "destination_fqdn": _flow_destination(path),
        "verdict": "FORWARDED",
        "bytes": byte_count,
    }
    directory = os.path.dirname(FLOW_FEED_PATH)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with FLOW_LOCK:
        with open(FLOW_FEED_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, separators=(",", ":")) + "\n")


def _write_provider_event(handler, path, body):
    """Persist content-free receiver evidence only; never the body or matched values."""
    if not EVENT_PATH:
        return
    global EVENT_SEQUENCE
    placeholders = MASK_PLACEHOLDER.findall(body)
    with EVENT_LOCK:
        EVENT_SEQUENCE += 1
        placeholder_classes = []
        for placeholder in placeholders:
            if placeholder not in PLACEHOLDER_CLASSES:
                PLACEHOLDER_CLASSES[placeholder] = len(PLACEHOLDER_CLASSES) + 1
            placeholder_classes.append(PLACEHOLDER_CLASSES[placeholder])
        if "/v1/messages/count_tokens" in path:
            request_kind = "token-count"
        elif "/v1/messages" in path or "/responses" in path:
            request_kind = "model"
        else:
            request_kind = "control-plane"
        event = {
            "sequence": EVENT_SEQUENCE,
            "provider": "anthropic" if "/v1/messages" in path else "openai",
            "request_kind": request_kind,
            "request_bytes": len(body),
            "protected_occurrences": sum(body.count(value) for value in PROTECTED_VALUES),
            "placeholder_occurrences": len(placeholders),
            "placeholder_identity_classes": placeholder_classes,
            "internal_headers_present": any(
                name.lower().startswith("x-hamza-") for name in handler.headers.keys()
            ),
            # Receiver-side equality only. The evidence never carries either auth value.
            "authorization_expected": (
                (not EXPECTED_X_API_KEY
                 or handler.headers.get("x-api-key", "") == EXPECTED_X_API_KEY)
                if "/v1/messages" in path
                else (not EXPECTED_AUTH
                      or handler.headers.get("Authorization", "") == EXPECTED_AUTH)
            ),
            "content_length_valid": (
                handler.headers.get("Content-Length") is None
                or int(handler.headers.get("Content-Length", "0")) == len(body)
            ),
        }
        directory = os.path.dirname(EVENT_PATH)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(EVENT_PATH, "a", encoding="utf-8") as evidence:
            evidence.write(json.dumps(event, separators=(",", ":"), sort_keys=True) + "\n")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # quieter default logging
        pass

    def do_GET(self):
        if self.path == "/health":
            self._respond(200, b"ok\n", "text/plain")
        else:
            self._respond(404, b"not found\n", "text/plain")

    def do_POST(self):
        body = self._read_body()
        _write_flow_event(self.path, len(body))
        _write_provider_event(self, self.path, body)
        # Echo back the requested model as the served model when present.
        requested_model = "gpt-5-codex"
        try:
            parsed = json.loads(body) if body else {}
            requested_model = parsed.get("model", requested_model)
        except json.JSONDecodeError:
            pass
        # Test aids: report whether the secret leaked through or arrived redacted.
        leaked_akia = b"AKIA" in body
        leaked_stripe = b"sk_live_" in body
        redacted = "redacted".encode() in body
        _log(f"POST {self.path} bytes={len(body)} model={requested_model} "
             f"leaked_akia={leaked_akia} leaked_stripe={leaked_stripe} redacted={redacted}")
        if "/v1/messages" in self.path:
            self._stream_sse(self._anthropic_events(requested_model))
        else:
            self._stream_sse(self._events(requested_model))

    def _read_body(self):
        # Envoy's ext_proc STREAMED mode strips Content-Length and forwards the body
        # chunked; a Provider must speak chunked transfer-encoding to receive it.
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            body = b""
            while True:
                size_line = self.rfile.readline().strip()
                try:
                    size = int(size_line.split(b";")[0], 16)
                except ValueError:
                    break
                if size == 0:
                    self.rfile.readline()  # CRLF closing the terminal chunk
                    break
                body += self.rfile.read(size)
                self.rfile.readline()  # CRLF after each chunk payload
            return body
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    def _stream_sse(self, events):
        # SSE has no Content-Length; signal end-of-body by closing the connection so
        # the client (and Envoy) sees EOF.
        self.close_connection = True
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        for event, data in events:
            if event == "[DONE]":
                self.wfile.write(b"data: [DONE]\n\n")
            else:
                self.wfile.write(f"event: {event}\ndata: {json.dumps(data)}\n\n".encode("utf-8"))
            self.wfile.flush()

    @staticmethod
    def _events(model):
        resp = {"id": "resp_fake_1", "model": model}
        yield "response.created", {
            "type": "response.created",
            "response": {**resp, "status": "in_progress"},
        }
        yield "response.output_item.added", {
            "type": "response.output_item.added",
            "output_index": 0,
            "item": {"type": "message", "role": "assistant"},
        }
        yield "response.completed", {
            "type": "response.completed",
            "response": {**resp, "status": "completed", "usage": USAGE},
        }
        yield "[DONE]", None

    @staticmethod
    def _anthropic_events(model):
        # Anthropic Messages SSE. Token math normalises to: input = 50+10+0 = 60,
        # cached = 10, output = 25, total = 85 (same invariants as OpenAI).
        yield "message_start", {
            "type": "message_start",
            "message": {"id": "msg_fake_1", "model": model,
                        "usage": {"input_tokens": 50, "cache_read_input_tokens": 10,
                                  "cache_creation_input_tokens": 0, "output_tokens": 1}},
        }
        yield "content_block_start", {
            "type": "content_block_start", "index": 0,
            "content_block": {"type": "text", "text": ""},
        }
        yield "content_block_delta", {
            "type": "content_block_delta", "index": 0,
            "delta": {"type": "text_delta", "text": "Hello"},
        }
        yield "content_block_stop", {"type": "content_block_stop", "index": 0}
        yield "message_delta", {
            "type": "message_delta", "delta": {"stop_reason": "end_turn"},
            "usage": {"output_tokens": 25},
        }
        yield "message_stop", {"type": "message_stop"}

    def _respond(self, code, body, content_type):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    _log(f"listening on :{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
