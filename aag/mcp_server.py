# -*- coding: utf-8 -*-
"""Local MCP server exposing audit-gateway's adjudication as an MCP tool.

Transport: stdio (Local MCP). The user runs this server themselves; no remote
endpoint, no hosted service, no payment. Credentials/registry stay local.

Run:
    python -m aag.mcp_server            # stdio MCP server
Tools exposed:
    audit_call  -- adjudicate one tool-call request (fail-closed)
"""
from __future__ import annotations

import os
import sys

from mcp.server.fastmcp import FastMCP

from .handler import _pick_registry_path, DEFAULT_REGISTRY_NAME
from .pipeline import AuditPipeline

mcp = FastMCP(
    "agent-audit-gateway",
    instructions=(
        "Fail-closed audit gateway. Adjudicate an agent tool-call request "
        "against policy rules before execution. Deny-by-default: any missing/"
        "malformed input yields a deny decision, never an allow."
    ),
)


def _build_pipeline() -> AuditPipeline:
    env_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    registry_path = _pick_registry_path(env_root, DEFAULT_REGISTRY_NAME)
    registry = __import__("aag.auth", fromlist=["CallerRegistry"]).CallerRegistry.from_file(registry_path)
    return AuditPipeline(registry=registry)


_pipeline = _build_pipeline()


@mcp.tool(
    name="audit_call",
    description=(
        "Adjudicate a single agent tool-call request against policy. "
        "Returns a decision (allow/deny), reason_code, risk_level, matched "
        "rules, trace_id and latency. Fail-closed: malformed input -> deny."
    ),
)
def audit_call(
    caller_id: str,
    credential: str,
    target_capability: str,
    action_type: str,
    data_class: str,
    request_hash: str,
    nonce: str,
    timestamp: float,
    idempotency_key: str | None = None,
    amount: float | None = None,
    payload: dict | None = None,
    currency: str = "CNY",
) -> dict:
    """Adjudicate one tool-call. See AuditRequest for field semantics."""
    request = {
        "caller_id": caller_id,
        "credential": credential,
        "target_capability": target_capability,
        "action_type": action_type,
        "data_class": data_class,
        "request_hash": request_hash,
        "nonce": nonce,
        "timestamp": timestamp,
        "idempotency_key": idempotency_key,
        "amount": amount,
    }
    return _pipeline.adjudicate(request, payload=payload, currency=currency)


def main(argv=None) -> int:
    # stdio transport = Local MCP (user-run, no remote endpoint)
    mcp.run(transport="stdio")
    return 0


if __name__ == "__main__":
    sys.exit(main())