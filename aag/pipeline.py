# -*- coding: utf-8 -*-
"""Wrap the vendored AuditGuard engine with a wall-clock timeout and a
fail-closed error mapping. The gateway never re-implements adjudication.

Fail-closed guarantees:
  - Any unexpected exception -> deny (ERR_INTERNAL).
  - Adjudication exceeding timeout_ms -> deny (ERR_TIMEOUT) without waiting
    for the engine.
  - Structural/context errors -> deny with the engine's reason_code.
"""
import threading
import time

from audit_guard.engine import AuditGuard
from audit_guard.models import ACTION_TYPES, DATA_CLASSES, AuditRequest
from audit_guard.rules import RuleSet

from .auth import CallerRegistry

DEFAULT_TIMEOUT_MS = 2000


class AuditPipeline:
    """A thin, timeout-guarded adapter over AuditGuard."""

    def __init__(self, ruleset=None, registry=None, timeout_ms=DEFAULT_TIMEOUT_MS):
        self.ruleset = ruleset if ruleset is not None else RuleSet.demo()
        self.registry = registry if registry is not None else CallerRegistry([])
        self.guard = AuditGuard(ruleset=self.ruleset)
        self.timeout_ms = timeout_ms
        # seed the guard identity registry from credential hashes (registry is
        # the single source of truth; no plaintext credential ever needed).
        for caller_id, cred_hash in self.registry.caller_hashes().items():
            info = self.registry.caller_info(caller_id) or {}
            self.ruleset.register_caller(
                caller_id,
                capabilities=info.get("capabilities", []),
                max_action=info.get("max_action", "read"),
                max_data_class=info.get("max_data_class", "public"),
            )
            self.guard._creds[caller_id] = cred_hash  # noqa: SLF001 (vendored engine)

    # ------------------------------------------------------------------ API
    def adjudicate(self, request: dict, payload=None, currency: str = "CNY") -> dict:
        """Run one audit call. Returns a dict, never raises for adjudication.

        request keys mirror AuditRequest fields:
            caller_id, credential, target_capability, action_type, data_class,
            request_hash, nonce, timestamp, idempotency_key, amount
        """
        started = time.monotonic()
        try:
            req = self._build_request(request, payload, currency)
        except Exception as exc:  # noqa: BLE001 - fail-closed
            return self._outcome("deny", "ERR_BAD_REQUEST", "high", [],
                                 latency_ms=_latency(started),
                                 fail_closed=True, reason=str(exc))

        container = {}

        def _run():
            try:
                verdict = self.guard.evaluate(req)
                container["verdict"] = verdict
            except Exception as exc:  # noqa: BLE001 - never allow
                container["error"] = exc

        worker = threading.Thread(target=_run, daemon=True)
        worker.start()
        worker.join(timeout=self.timeout_ms / 1000.0)
        if worker.is_alive():
            return self._outcome("deny", "ERR_TIMEOUT", "high", [],
                                 latency_ms=_latency(started),
                                 fail_closed=True,
                                 reason="adjudication exceeded %dms" % self.timeout_ms)

        if "error" in container:
            err = container["error"]
            return self._outcome("deny", "ERR_INTERNAL", "high", [],
                                 latency_ms=_latency(started), fail_closed=True,
                                 reason="gateway fail-closed: %s" % type(err).__name__)

        verdict = container["verdict"]
        return {
            "decision": verdict.decision,
            "reason_code": verdict.reason_code,
            "risk_level": verdict.risk_level,
            "matched_rules": verdict.matched_rules,
            "trace_id": verdict.trace_id,
            "created_at": verdict.created_at,
            "idempotent_replay": verdict.idempotent_replay,
            "latency_ms": _latency(started),
            "fail_closed": False,
        }

    # -------------------------------------------------------------- helpers
    def _build_request(self, request: dict, payload, currency: str) -> AuditRequest:
        if not isinstance(request, dict):
            raise ValueError("request must be an object")
        required = ("caller_id", "credential", "target_capability", "action_type",
                    "data_class", "request_hash", "nonce", "timestamp")
        for field in required:
            if field not in request:
                raise ValueError("missing field: %s" % field)
        action_type = request["action_type"]
        data_class = request["data_class"]
        if action_type not in ACTION_TYPES:
            raise ValueError("unknown action_type: %s" % action_type)
        if data_class not in DATA_CLASSES:
            raise ValueError("unknown data_class: %s" % data_class)
        try:
            timestamp = float(request.get("timestamp"))
        except (TypeError, ValueError):
            raise ValueError("timestamp must be numeric")
        return AuditRequest(
            caller_id=str(request["caller_id"]),
            credential=str(request["credential"]),
            target_capability=str(request["target_capability"]),
            action_type=action_type,
            data_class=data_class,
            request_hash=str(request["request_hash"]),
            nonce=str(request["nonce"]),
            timestamp=timestamp,
            idempotency_key=request.get("idempotency_key"),
            amount=request.get("amount"),
            payload=payload,
            currency=currency or "CNY",
        )

    @staticmethod
    def _outcome(decision, reason_code, risk_level, matched_rules, latency_ms,
                 fail_closed, reason=""):
        return {
            "decision": decision,
            "reason_code": reason_code,
            "risk_level": risk_level,
            "matched_rules": list(matched_rules),
            "trace_id": "",
            "created_at": 0.0,
            "idempotent_replay": False,
            "latency_ms": latency_ms,
            "fail_closed": fail_closed,
            "reason": reason,
        }


def _latency(started):
    return round((time.monotonic() - started) * 1000, 2)