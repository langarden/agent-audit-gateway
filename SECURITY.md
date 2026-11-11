# Security

## Reporting a vulnerability

Please report vulnerabilities privately to the maintainers at
`2307788504@qq.com`. Do not open a public issue for security problems.

## Design posture

**Fail-closed.** The gateway assumes the worst about callers and traffic:

- no listening socket unless `AUDIT_GATEWAY_ENABLE=1` (loopback by default)
- unknown/disabled caller -> deny
- malformed body -> deny
- engine timeout -> deny (`ERR_TIMEOUT`) without consulting the engine
- engine exception -> deny (`ERR_INTERNAL`)
- registry load failure -> deny

## Status

**Research prototype / reference implementation**, not a hardened production
product. The vendored engine is the same MIT engine from agent-call-audit
v0.1.0; review it before relying on it in production.

## Responsible disclosure

- Do not test on third-party systems.
- Do not include real secrets or credentials in any issue or commit.
- Include a minimal repro (request + commands) when possible.