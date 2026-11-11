# -*- coding: utf-8 -*-
"""Gate-level walkthrough: pip-installable, no network needed.

Shows: allow, auth deny, red-line deny, replay deny, hash-mismatch deny,
permission deny, and the fail-closed timeout.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aag import AuditPipeline, CallerRegistry
from audit_guard.engine import hash_payload

TOKENS = {
    "agent-alpha": "gateway-token-alpha-2026",
    "agent-readonly": "gateway-token-readonly-2026",
}

REGISTRY = {
    "callers": [
        {
            "caller_id": "agent-alpha",
            "credential_hash": "sha256:886b1fd37e243f485a84883b2f65120a93afe55b88c2ace5005f812258b9fdbe",
            "status": "active",
            "capabilities": ["data.lookup", "content.publish", "money.transfer"],
            "max_action": "spend",
            "max_data_class": "internal",
        },
        {
            "caller_id": "agent-readonly",
            "credential_hash": "sha256:6d5899a3394e2af0ede7f7542b82840fc2e180e2453501489c3c3def5ddaa76e",
            "status": "active",
            "capabilities": ["data.lookup"],
            "max_action": "read",
            "max_data_class": "public",
        },
    ]
}


def main():
    pipeline = AuditPipeline(registry=CallerRegistry.from_dict(REGISTRY), timeout_ms=2000)
    nonce = 0

    def req(**over):
        nonlocal nonce
        base = {
            "caller_id": "agent-alpha",
            "credential": TOKENS["agent-alpha"],
            "target_capability": "data.lookup",
            "action_type": "read",
            "data_class": "public",
            "request_hash": hash_payload({"q": "k"}),  # matches payload below if given
            "nonce": "demo-%d" % nonce,
            "timestamp": time.time(),
        }
        nonce += 1
        base.update(over)
        return base

    print("1) allow (read public via data.lookup)")
    print("   ->", pipeline.adjudicate(req(), payload={"q": "k"}))

    print("2) auth deny (wrong token)")
    print("   ->", pipeline.adjudicate(req(credential="wrong-token")))

    print("3) red-line deny (outbound restricted)")
    print("   ->", pipeline.adjudicate(req(
        target_capability="content.publish", action_type="outbound",
        data_class="restricted")))

    print("4) replay deny (same nonce twice)")
    replay = req()
    pipeline.adjudicate(replay, payload=None)
    print("   ->", pipeline.adjudicate(replay, payload=None))

    print("5) hash-mismatch deny (payload changed)")
    print("   ->", pipeline.adjudicate(req(), payload={"q": "DIFFERENT"}))

    print("6) least-privilege deny (readonly caller tries spend)")
    print("   ->", pipeline.adjudicate(req(
        caller_id="agent-readonly", credential=TOKENS["agent-readonly"],
        target_capability="money.transfer", action_type="spend",
        data_class="internal", amount=10.0)))

    print("7) timeout deny (fail-closed, budget=50ms, slow engine)")
    slow = AuditPipeline(registry=CallerRegistry.from_dict(REGISTRY), timeout_ms=50)

    import time as _time

    def slow_evaluate(*_a, **_k):
        _time.sleep(0.3)
        raise AssertionError("engine must not be consulted after timeout")

    slow.guard.evaluate = slow_evaluate
    print("   ->", slow.adjudicate(req()))


if __name__ == "__main__":
    main()