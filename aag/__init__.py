# -*- coding: utf-8 -*-
"""agent-audit-gateway (aag): an HTTP gateway around the vendored
agent-call-audit engine, fail-closed by default.

Design:
  - The gateway is TRANSPORT + AUTH + RATE-LIMIT only. Adjudication runs in
    the vendored AuditGuard engine; a gateway fault can never ALLOW.
  - Default OFF: no listening socket unless AUDIT_GATEWAY_ENABLE=1.
    Even when enabled it binds loopback by default.
  - Wall-clock timeout >= 2000ms -> deny (ERR_TIMEOUT) without consulting
    the engine (fail-closed).
  - Bearer tokens are checked against sha256 hashes in the caller registry;
    plaintext credentials never touch disk or logs.

Research prototype / AI-assisted development. MIT licensed.
"""

from .auth import CallerRegistry, hash_credential
from .limiter import RateLimiter
from .pipeline import AuditPipeline
from .server import main as run_gateway

__all__ = [
    "CallerRegistry",
    "hash_credential",
    "RateLimiter",
    "AuditPipeline",
    "run_gateway",
]

__version__ = "0.1.0"