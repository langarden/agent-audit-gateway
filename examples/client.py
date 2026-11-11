# -*- coding: utf-8 -*-
"""Example HTTP client for the audit gateway.

Usage:
    1. Start the gateway (loopback):
       set AUDIT_GATEWAY_ENABLE=1
       set AUDIT_GATEWAY_PORT=12787
       python -m aag.server
    2. In another shell:
       python examples/client.py
"""
import hashlib
import json
import sys
import time
import urllib.request

BASE = "http://127.0.0.1:12787"


def hash_payload(obj):
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def audit_call(request, payload=None, token="gateway-token-alpha-2026"):
    body = json.dumps({"request": request, "payload": payload}).encode("utf-8")
    r = urllib.request.Request(
        BASE + "/audit_call",
        data=body,
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def main():
    request = {
        "caller_id": "agent-alpha",
        "credential": "gateway-token-alpha-2026",
        "target_capability": "data.lookup",
        "action_type": "read",
        "data_class": "public",
        "request_hash": hash_payload({"q": "hello"}),
        "nonce": "client-%d" % time.time(),
        "timestamp": time.time(),
    }
    code, body = audit_call(request, payload={"q": "hello"})
    print("status:", code)
    print(json.dumps(body, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()