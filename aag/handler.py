# -*- coding: utf-8 -*-
"""HTTP handler: POST /audit_call only. Transport + auth + rate-limit.

The handler never touches adjudication logic; it parses the body, authenticates
the bearer token, and delegates to AuditPipeline. Any fault -> JSON deny shape.
"""
import json
import os
from http.server import BaseHTTPRequestHandler

from .auth import CallerRegistry
from .limiter import RateLimiter
from .pipeline import AuditPipeline

DEFAULT_REGISTRY_NAME = "callers.registry.example.json"


def _pick_registry_path(env_root, name):
    real = os.path.join(env_root, "rules", "callers.registry.json")
    if os.path.exists(real):
        return real
    return os.path.join(env_root, "rules", name)


class AuditGatewayHandler(BaseHTTPRequestHandler):
    """POST /audit_call with Authorization: Bearer <token>."""

    server_version = "AgentAuditGateway/0.1"
    protocol_version = "HTTP/1.1"

    # injected per-server via attributes below (set by server.run())
    gateway_pipeline = None
    rate_limiter = None

    def _send(self, code: int, payload: dict):
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def do_POST(self):  # noqa: N802 (http.server naming)
        from urllib.parse import urlparse

        parsed = urlparse(self.path)
        if parsed.path != "/audit_call":
            self._send(404, {"decision": "deny", "error": "ERR_NOT_FOUND",
                             "reason": "only POST /audit_call"})
            return

        client = self.client_address[0] if self.client_address else "?"
        if not self.rate_limiter.allow(client):
            self._send(429, {"decision": "deny", "error": "ERR_RATE_LIMITED",
                             "reason": "rate limit exceeded (gateway transport)"})
            return

        token = ""
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[len("Bearer "):].strip()
        caller = self.gateway_pipeline.registry.authenticate(token)
        if caller is None:
            self._send(401, {"decision": "deny", "error": "ERR_AUTH_FAILED",
                             "reason": "gateway auth failed (fail-closed)"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length > 0 else b"{}"
            body = json.loads(raw.decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            self._send(400, {"decision": "deny", "error": "ERR_BAD_REQUEST",
                             "reason": "invalid JSON body: %s" % type(exc).__name__})
            return

        request = body.get("request")
        if not isinstance(request, dict):
            self._send(400, {"decision": "deny", "error": "ERR_BAD_REQUEST",
                             "reason": "missing 'request' object"})
            return

        result = self.gateway_pipeline.adjudicate(
            request,
            payload=body.get("payload"),
            currency=body.get("currency"),
        )
        self._send(200, {"caller_id": caller, **result})

    def log_message(self, *args):  # keep console quiet; no creds anyway
        return


def build_handler(pipeline: AuditPipeline, rate_limiter: RateLimiter):
    """Bind pipeline + limiter to the handler class (per-server injection)."""
    pipe = pipeline
    lim = rate_limiter

    class _Bound(AuditGatewayHandler):
        gateway_pipeline = pipe
        rate_limiter = lim

    return _Bound