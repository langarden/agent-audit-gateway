# -*- coding: utf-8 -*-
"""Fail-closed posture tests: missing registry, empty registry, broken engine."""
import time
import unittest

from aag.auth import CallerRegistry
from aag.pipeline import AuditPipeline
from audit_guard.engine import hash_payload


def req(**over):
    r = {
        "caller_id": "agent-alpha",
        "credential": "anything",
        "target_capability": "data.lookup",
        "action_type": "read",
        "data_class": "public",
        "request_hash": hash_payload(None),
        "nonce": "fc-%f" % time.time(),
        "timestamp": time.time(),
    }
    r.update(over)
    return r


class FailClosedTests(unittest.TestCase):
    def test_empty_registry_denies_all(self):
        p = AuditPipeline(registry=CallerRegistry.from_dict({"callers": []}))
        out = p.adjudicate(req())
        self.assertEqual(out["decision"], "deny")
        self.assertEqual(out["reason_code"], "ERR_AUTH_FAILED")

    def test_engine_failure_never_allows(self):
        p = AuditPipeline(
            registry=CallerRegistry.from_dict({
                "callers": [{
                    "caller_id": "agent-alpha",
                    "credential_hash": "sha256:" + __import__("hashlib").sha256(
                        b"tok").hexdigest(),
                    "status": "active",
                    "capabilities": ["data.lookup"],
                    "max_action": "read",
                    "max_data_class": "public",
                }]
            }),
            timeout_ms=500,
        )

        def broken(*_a, **_k):
            raise RuntimeError("engine exploded")

        p.guard.evaluate = broken
        out = p.adjudicate(req(credential="tok"))
        self.assertEqual(out["decision"], "deny")
        self.assertEqual(out["reason_code"], "ERR_INTERNAL")
        self.assertTrue(out["fail_closed"])

    def test_bad_request_deny_shape(self):
        p = AuditPipeline(registry=CallerRegistry([]))
        out = p.adjudicate("not-a-dict")
        self.assertEqual(out["decision"], "deny")
        self.assertEqual(out["reason_code"], "ERR_BAD_REQUEST")

    def test_timestamp_non_numeric_deny(self):
        p = AuditPipeline(registry=CallerRegistry([]))
        out = p.adjudicate({
            "caller_id": "x", "credential": "y", "target_capability": "z",
            "action_type": "read", "data_class": "public",
            "request_hash": "0" * 64, "nonce": "1", "timestamp": "not-a-number",
        })
        self.assertEqual(out["reason_code"], "ERR_BAD_REQUEST")


if __name__ == "__main__":
    unittest.main()