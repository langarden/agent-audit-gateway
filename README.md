# agent-audit-gateway

> **An HTTP audit gateway for AI agent tool calls** — transport + bearer auth +
> rate limit in front of a fail-closed audit engine. **Default OFF. Loopback by
> default. A gateway fault can never ALLOW.**

```bash
pip install agent-audit-gateway          # zero deps, Python 3.9+
```

![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Tests](https://img.shields.io/badge/tests-34%20passed-green)
![Deps](https://img.shields.io/badge/runtime%20deps-0-green)
![Status](https://img.shields.io/badge/status-research%20prototype-orange)

<a href="https://gitcode.com/gcw_MKhSyoGN/agent-audit-gateway"><img src="https://img.shields.io/badge/GitCode-gcw_MKhSyoGN%2Fagent-audit-gateway-blue" alt="GitCode"></a>
<a href="https://github.com/langarden/agent-audit-gateway"><img src="https://img.shields.io/badge/GitHub-langarden%2Fagent-audit-gateway-black" alt="GitHub"></a>

[中文版](docs/README.zh-CN.md) · *Research prototype / AI-assisted development.*

---

Deploy one endpoint, `POST /audit_call`, and every agent tool invocation gets a
verdict (allow / deny / human) with a verifiable trail — without rewriting your
agent framework. The gateway **never re-implements adjudication**: it is
transport, bearer auth and rate limiting only.

## Why a gateway?

Your agent already has capabilities; what it lacks is an **enforcement point**
between the caller and the action. `agent-audit-gateway` gives you:

- **transport layer only** — adjudication lives in the vendored engine
- **hash-only credentials** — caller registry stores sha256, never plaintext
- **timeout = deny** — an adjudication over budget returns `ERR_TIMEOUT`
  without consulting the engine (fail-closed)
- **default OFF** — no listening socket unless you opt in; loopback by default

## Product family

Part of the **Verifiable-agent family** — one fail-closed design language:

| Repo | Role |
|:--|:--|
| [agent-call-audit](https://gitcode.com/gcw_MKhSyoGN/agent-call-audit) | audit **engine** for agent tool calls |
| [agent-memory-ledger](https://gitcode.com/gcw_MKhSyoGN/agent-memory-ledger) | verifiable **memory** layer |
| **agent-audit-gateway** | the engine as an HTTP **gateway** (this repo) |
| [agent-route-grid](https://gitcode.com/gcw_MKhSyoGN/agent-route-grid) | audited multi-agent **routing** |

The engine is **vendored** (`audit_guard/`, from agent-call-audit v0.1.0, same
MIT maintainers) so this package is self-contained with zero dependencies.

## Install

```bash
pip install agent-audit-gateway   # once published
# dev / from source:
pip install -e .
```

Zero runtime dependencies. Python 3.9+.

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

## Run the HTTP gateway (default OFF)

```bash
set AUDIT_GATEWAY_ENABLE=1
set AUDIT_GATEWAY_PORT=12787
python -m aag.server
```

Then call it: `python examples/client.py`.

## Proof of life

Real output from `python examples/demo.py` (seven scenarios):

```
1) allow                    -> decision=allow  FAIL_CLOSED=False
2) auth deny (bad token)    -> ERR_AUTH_FAILED
3) red-line deny            -> ERR_RED_LINE (DEMO-RL-001)
4) replay deny (same nonce) -> ERR_REPLAY
5) hash-mismatch deny       -> ERR_HASH_MISMATCH
6) least-privilege deny     -> ERR_CAPABILITY_NOT_GRANTED
7) timeout (50ms budget)    -> ERR_TIMEOUT  FAIL_CLOSED=True
```

## Fail-closed invariants

| Invariant | Guarantee |
|:--|:--|
| Default OFF | no listening socket unless `AUDIT_GATEWAY_ENABLE=1`; loopback by default |
| Transport only | adjudication stays in the vendored engine; gateway never allows |
| Auth fail-closed | `Bearer` token vs sha256 registry; missing/unknown/disabled -> deny |
| Timeout deny | adjudication over `timeout_ms` -> `ERR_TIMEOUT` without the engine |
| Error -> deny | any unexpected exception maps to `ERR_INTERNAL` deny |
| Rate limited | per-IP fixed window; transport-level only |
| No secrets on disk | registry stores sha256 hashes only |

## HTTP API

```
POST /audit_call
Authorization: Bearer <token>
{ "request": { caller_id, credential, target_capability, action_type, data_class,
               request_hash, nonce, timestamp },
  "payload": {...} | null }
→ { caller_id, decision, reason_code, risk_level, matched_rules,
    trace_id, latency_ms, fail_closed }
```

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
tests/           34 tests (incl. loopback HTTP integration)
```

## Roadmap ideas

- Streamable HTTP / MCP binding over the same pipeline
- OpenTelemetry-style audit event export
- Caller registry rotation with dual confirmation

## Contributing / Security / License

- [CONTRIBUTING.md](CONTRIBUTING.md) — fail-closed first, sanitized commits,
  green tests.
- [SECURITY.md](SECURITY.md) — report privately; reference implementation.
- [LICENSE](LICENSE) — MIT, `agent-audit-gateway maintainers`. Engine vendored
  from agent-call-audit (MIT).