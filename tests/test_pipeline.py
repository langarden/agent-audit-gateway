# -*- coding: utf-8 -*-
import time
import unittest

from aag.auth import CallerRegistry
from aag.pipeline import AuditPipeline
from audit_guard.engine import hash_payload

TOKENS = {
    # DEMO DATA — NOT A REAL CREDENTIAL
    "agent-alpha": "gateway-token-alpha-2026",
    "agent-readonly": "gateway-token-readonly-2026",
}

REG = {
    "callers": [
        {"caller_id": "agent-alpha",
         "credential_hash": "sha256:886b1fd37e243f485a84883b2f65120a93afe55b88c2ace5005f812258b9fdbe",
         "status": "active",
         "capabilities": ["data.lookup", "content.publish", "money.transfer"],
         "max_action": "spend", "max_data_class": "internal"},
        {"caller_id": "agent-readonly",
         "credential_hash": "sha256:6d5899a3394e2af0ede7f7542b82840fc2e180e2453501489c3c3def5ddaa76e",
         "status": "active",
         "capabilities": ["data.lookup", "money.transfer"],
         "max_action": "read", "max_data_class": "public"},
    ]
}


def base_req(**over):
    r = {
        "caller_id": "agent-alpha",
        "credential": TOKENS["agent-alpha"],
        "target_capability": "data.lookup",
        "action_type": "read",
        "data_class": "public",
        "request_hash": hash_payload({"q": "k"}),
        "nonce": "n-%f" % time.time(),
        "timestamp": time.time(),
    }
    r.update(over)
    return r


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.p = AuditPipeline(registry=CallerRegistry.from_dict(REG), timeout_ms=2000)

    def test_allow(self):
        out = self.p.adjudicate(base_req(), payload={"q": "k"})
        self.assertEqual(out["decision"], "allow")
        self.assertFalse(out["fail_closed"])

    def test_auth_deny(self):
        out = self.p.adjudicate(base_req(credential="wrong"))
        self.assertEqual(out["decision"], "deny")
        self.assertEqual(out["reason_code"], "ERR_AUTH_FAILED")

    def test_unknown_capability(self):
        out = self.p.adjudicate(base_req(target_capability="nope.x"))
        self.assertEqual(out["reason_code"], "ERR_UNKNOWN_CAPABILITY")

    def test_permission_deny(self):
        out = self.p.adjudicate(base_req(
            caller_id="agent-readonly", credential=TOKENS["agent-readonly"],
            target_capability="money.transfer", action_type="spend",
            data_class="internal", amount=10.0))
        self.assertEqual(out["decision"], "deny")
        self.assertEqual(out["reason_code"], "ERR_PERMISSION_ACTION")

    def test_red_line_deny(self):
        out = self.p.adjudicate(base_req(
            target_capability="content.publish", action_type="outbound",
            data_class="restricted"))
        self.assertEqual(out["decision"], "deny")
        self.assertEqual(out["reason_code"], "ERR_RED_LINE")
        self.assertIn("DEMO-RL-001", out["matched_rules"])

    def test_replay_deny(self):
        req = base_req()
        first = self.p.adjudicate(req, payload=None)
        second = self.p.adjudicate(req, payload=None)
        self.assertEqual(first["decision"], "allow")
        self.assertEqual(second["reason_code"], "ERR_REPLAY")

    def test_hash_mismatch_deny(self):
        out = self.p.adjudicate(base_req(), payload={"q": "DIFFERENT"})
        self.assertEqual(out["reason_code"], "ERR_HASH_MISMATCH")

    def test_bad_request_missing_field(self):
        req = base_req()
        del req["nonce"]
        out = self.p.adjudicate(req)
        self.assertEqual(out["decision"], "deny")
        self.assertEqual(out["reason_code"], "ERR_BAD_REQUEST")

    def test_bad_request_bad_action(self):
        out = self.p.adjudicate(base_req(action_type="teleport"))
        self.assertEqual(out["reason_code"], "ERR_BAD_REQUEST")

    def test_timeout_fail_closed(self):
        slow = AuditPipeline(registry=CallerRegistry.from_dict(REG), timeout_ms=50)

        def slow_evaluate(*_a, **_k):
            time.sleep(0.3)
            raise AssertionError("should never be consulted")

        slow.guard.evaluate = slow_evaluate  # inject slow engine
        out = slow.adjudicate(base_req())
        self.assertEqual(out["decision"], "deny")
        self.assertEqual(out["reason_code"], "ERR_TIMEOUT")
        self.assertTrue(out["fail_closed"])


if __name__ == "__main__":
    unittest.main()