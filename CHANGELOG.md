# Changelog

## v0.1.0 (2026-11-11)

- Initial public release candidate.
- Gateway layer: `aag/auth.py` (sha256-hash caller registry, fail-closed),
  `aag/limiter.py` (fixed-window rate limiter), `aag/pipeline.py`
  (timeout-guarded engine adapter), `aag/handler.py` (POST /audit_call HTTP
  handler), `aag/server.py` (default-OFF launcher, loopback only).
- Vendored engine: `audit_guard/` from agent-call-audit v0.1.0 (verbatim,
  MIT, same maintainers) so the package is self-contained with zero deps.
- Examples: `examples/demo.py` (seven-scenario walkthrough) + `examples/client.py`.
- Tests: 34 unit + loopback HTTP integration tests covering auth, rate limit,
  timeout, fail-closed posture, and error-code transparency.