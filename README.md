# agent-audit-gateway

An **HTTP audit gateway** for AI agent tool calls: transport + auth +
rate-limit in front of a fail-closed audit engine. Deploy one endpoint,
`POST /audit_call`, and every agent tool invocation gets a verdict
(allow / deny / human) with a verifiable trail.

*Research prototype / AI-assisted development. MIT licensed.*

## Why

[agent-call-audit](https://gitcode.com/gcw_MKhSyoGN/agent-call-audit) is the
engine; this repository is the deployable service layer around it. The gateway
**never re-implements adjudication** — it is transport, bearer auth and rate
limiting only. A gateway fault can never ALLOW (fail-closed).

## Install

```bash
pip install agent-audit-gateway   # once published
# dev / from source:
pip install -e .
```

Zero runtime dependencies. Python 3.9+. The audit engine is vendored
(`audit_guard/`, from agent-call-audit v0.1.0, same MIT maintainers) so the
package is self-contained.

## Quick start (library)

```python
from aag import AuditPipeline, CallerRegistry

pipeline = AuditPipeline(
    registry=CallerRegistry.from_file("rules/callers.registry.example.json"),
    timeout_ms=2000,
)
print(pipeline.adjudicate({
    "caller_id": "agent-alpha",
    "credential": "gateway-token-alpha-2026",
    "target_capability": "data.lookup",
    "action_type": "read",
    "data_class": "public",
    "request_hash": "…sha256 of optional payload…",
    "nonce": "n-1",
    "timestamp": 1700000000.0,
}))
```

Run the seven-scenario walkthrough:

```bash
python examples/demo.py
```

## Run the HTTP gateway (default OFF)

The gateway binds **nothing** unless you opt in. Even then it binds loopback.

```bash
set AUDIT_GATEWAY_ENABLE=1
set AUDIT_GATEWAY_PORT=12787
python -m aag.server
```

Then call it from another shell:

```bash
python examples/client.py
```

## API

`POST /audit_call` with `Authorization: Bearer <token>`

Request body:

```json
{
  "request": {
    "caller_id": "agent-alpha",
    "credential": "gateway-token-alpha-2026",
    "target_capability": "data.lookup",
    "action_type": "read",
    "data_class": "public",
    "request_hash": "sha256-of-payload",
    "nonce": "unique-per-caller",
    "timestamp": 1700000000.0
  },
  "payload": { "optional": "body" }
}
```

Response: `{ "caller_id", "decision", "reason_code", "risk_level",
"matched_rules", "trace_id", "latency_ms", "fail_closed" }`

## Fail-closed invariants

| Invariant | Guarantee |
|:--|:--|
| Default OFF | no listening socket unless `AUDIT_GATEWAY_ENABLE=1`; loopback by default |
| Transport only | adjudication stays in the vendored engine; gateway never allows |
| Auth fail-closed | `Bearer` token checked against sha256 registry; missing/unknown/disabled -> deny |
| Timeout deny | adjudication over `timeout_ms` -> `ERR_TIMEOUT` without consulting the engine |
| Error -> deny | any unexpected exception maps to `ERR_INTERNAL` deny, never allow |
| Rate limited | per-IP fixed window; transport-level only, never auth bypass |
| No secrets on disk | registry stores sha256 hashes only; no plaintext credentials |

## Architecture

```
audit_guard/   vendored engine from agent-call-audit v0.1.0 (verbatim, MIT)
aag/
├── auth.py       CallerRegistry: sha256 hash registry, fail-closed
├── limiter.py    fixed-window rate limiter
├── pipeline.py   AuditPipeline: timeout-guarded AuditGuard adapter
├── handler.py    HTTP handler (POST /audit_call)
└── server.py     launcher (AUDIT_GATEWAY_ENABLE-gated)
rules/           example caller registry (hashes only)
examples/        demo.py (library) + client.py (HTTP)
tests/           34 unit + loopback HTTP integration tests
```

## Contributing / Security

- [CONTRIBUTING.md](CONTRIBUTING.md) — fail-closed first, sanitized commits,
  green tests.
- [SECURITY.md](SECURITY.md) — report privately; reference implementation,
  not a hardened product.

## License

MIT — see [LICENSE](LICENSE). Maintainers: `agent-audit-gateway maintainers`.
Engine vendored from [agent-call-audit](https://gitcode.com/gcw_MKhSyoGN/agent-call-audit)
v0.1.0 (MIT).