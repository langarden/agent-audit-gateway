# -*- coding: utf-8 -*-
"""End-to-end loopback gateway tests: real HTTP server + real HTTP client."""
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from aag.auth import CallerRegistry
from aag.handler import build_handler
from aag.limiter import RateLimiter
from aag.pipeline import AuditPipeline
from audit_guard.engine import hash_payload

REGISTRY_JSON = {
    "callers": [
        {"caller_id": "agent-alpha",
         "credential_hash": "sha256:886b1fd37e243f485a84883b2f65120a93afe55b88c2ace5005f812258b9fdbe",
         "status": "active",
         "capabilities": ["data.lookup", "content.publish", "money.transfer"],
         "max_action": "spend", "max_data_class": "internal"},
    ]
}

TOKEN = "gateway-token-alpha-2026"  # DEMO DATA — NOT A REAL CREDENTIAL


class GatewayServer:
    def __init__(self, rate_max=100):
        self.tmp = tempfile.TemporaryDirectory()
        rules_dir = os.path.join(self.tmp.name, "rules")
        os.makedirs(rules_dir, exist_ok=True)
        with open(os.path.join(rules_dir, "callers.registry.example.json"), "w", encoding="utf-8") as f:
            json.dump(REGISTRY_JSON, f)
        registry = CallerRegistry.from_file(
            os.path.join(rules_dir, "callers.registry.example.json"))
        pipeline = AuditPipeline(registry=registry, timeout_ms=2000)
        handler = build_handler(pipeline, RateLimiter(rate_max, 60.0))
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.tmp.cleanup()


def post(port, path="/audit_call", body=None, token=TOKEN):
    data = json.dumps(body).encode("utf-8") if body is not None else b"{}"
    req = urllib.request.Request(
        "http://127.0.0.1:%d%s" % (port, path),
        data=data,
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def request_payload(nonce):
    return {
        "request": {
            "caller_id": "agent-alpha",
            "credential": TOKEN,
            "target_capability": "data.lookup",
            "action_type": "read",
            "data_class": "public",
            "request_hash": hash_payload({"q": "hello"}),
            "nonce": "http-%s-%f" % (nonce, time.time()),
            "timestamp": time.time(),
        },
        "payload": {"q": "hello"},
    }


class GatewayHttpTests(unittest.TestCase):
    def test_allow_roundtrip(self):
        srv = GatewayServer()
        try:
            status, body = post(srv.port, body=request_payload("t1"))
            self.assertEqual(status, 200)
            self.assertEqual(body["decision"], "allow")
            self.assertEqual(body["caller_id"], "agent-alpha")
            self.assertIn("latency_ms", body)
        finally:
            srv.close()

    def test_auth_failure(self):
        srv = GatewayServer()
        try:
            status, body = post(srv.port, body=request_payload("t2"), token="wrong-token")
            self.assertEqual(status, 401)
            self.assertEqual(body["error"], "ERR_AUTH_FAILED")
        finally:
            srv.close()

    def test_unknown_path_404(self):
        srv = GatewayServer()
        try:
            status, body = post(srv.port, path="/other", body={})
            self.assertEqual(status, 404)
            self.assertEqual(body["error"], "ERR_NOT_FOUND")
        finally:
            srv.close()

    def test_bad_json_400(self):
        srv = GatewayServer()
        try:
            req = urllib.request.Request(
                "http://127.0.0.1:%d/audit_call" % srv.port,
                data=b"{not-json",
                headers={"Authorization": "Bearer " + TOKEN},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                self.fail("should 400")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 400)
        finally:
            srv.close()

    def test_missing_request_400(self):
        srv = GatewayServer()
        try:
            status, body = post(srv.port, body={"payload": {"a": 1}})
            self.assertEqual(status, 400)
            self.assertEqual(body["error"], "ERR_BAD_REQUEST")
        finally:
            srv.close()

    def test_rate_limited(self):
        srv = GatewayServer(rate_max=3)
        try:
            for i in range(3):
                status, _ = post(srv.port, body=request_payload("rl%d" % i))
                self.assertEqual(status, 200)
            status, body = post(srv.port, body=request_payload("rl-4"))
            self.assertEqual(status, 429)
            self.assertEqual(body["error"], "ERR_RATE_LIMITED")
        finally:
            srv.close()

    def test_unregistered_caller_denied(self):
        srv = GatewayServer()
        try:
            body_req = request_payload("t3")
            body_req["request"]["caller_id"] = "agent-not-in-registry"
            body_req["request"]["credential"] = "no-such-token"
            status, body = post(srv.port, body=body_req, token="no-such-token")
            self.assertEqual(status, 401)
        finally:
            srv.close()


if __name__ == "__main__":
    unittest.main()