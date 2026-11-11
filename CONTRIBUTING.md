# Contributing

Thanks for considering contributing to agent-audit-gateway.

## Guiding principles

1. **Fail-closed first.** When in doubt, deny. The gateway must never gain a
   path that can ALLOW on a transport/parse fault.
2. **No new dependencies.** The project is zero-runtime-dependency by design;
   the engine is vendored intentionally.
3. **Sanitized commits.** No secrets, no personal/organization identifiers,
   no machine paths.
4. **Tests stay green.** Every change must keep the suite passing.

## Quick start

```bash
pip install -e .
python -m unittest discover -s tests -t . -v
python examples/demo.py
```

## Security posture

- Never log request bodies or bearer tokens.
- Caller registries store sha256 hashes only; real registries should never be
  committed (see `rules/callers.registry.example.json`).
- Any change that touches adjudication MUST be reviewed against the fail-closed
  invariants in README.

## Pull requests

- One logical change per PR.
- Add tests for new behavior; regression tests for bug fixes.
- Reference the invariant (README table) your change relates to.