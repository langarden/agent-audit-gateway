# -*- coding: utf-8 -*-
"""Gateway launcher. Default OFF (fail-closed): no socket unless
AUDIT_GATEWAY_ENABLE=1; even then it binds loopback by default.

Env knobs:
    AUDIT_GATEWAY_ENABLE=1        enable listening
    AUDIT_GATEWAY_HOST=127.0.0.1  bind host (loopback default)
    AUDIT_GATEWAY_PORT=12787      bind port
    AUDIT_GATEWAY_TIMEOUT_MS=2000 adjudication wall-clock budget
    AUDIT_GATEWAY_RATE_MAX=600    per-IP per-minute transport limit
"""
import os
import sys
from http.server import ThreadingHTTPServer

from .auth import CallerRegistry
from .handler import build_handler
from .limiter import RateLimiter
from .pipeline import AuditPipeline

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 12787
DEFAULT_TIMEOUT_MS = 2000
DEFAULT_RATE_MAX = 600


def build_pipeline(env_root=None, timeout_ms=None) -> AuditPipeline:
    env_root = env_root or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    registry = CallerRegistry.from_file(
        _registry_path(env_root)
    )
    return AuditPipeline(
        registry=registry,
        timeout_ms=timeout_ms or int(os.environ.get("AUDIT_GATEWAY_TIMEOUT_MS", DEFAULT_TIMEOUT_MS)),
    )


def _registry_path(env_root):
    from .handler import _pick_registry_path
    return _pick_registry_path(env_root, DEFAULT_REGISTRY_NAME)


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if os.environ.get("AUDIT_GATEWAY_ENABLE", "0") != "1":
        print("AUDIT_GATEWAY_ENABLE != 1: gateway stays OFF (default locked).")
        return 0

    try:
        port = int(os.environ.get("AUDIT_GATEWAY_PORT", str(DEFAULT_PORT)))
    except ValueError:
        return 1
    host = os.environ.get("AUDIT_GATEWAY_HOST", DEFAULT_HOST)
    rate_max = int(os.environ.get("AUDIT_GATEWAY_RATE_MAX", str(DEFAULT_RATE_MAX)))

    pipeline = build_pipeline()
    handler = build_handler(pipeline, RateLimiter(rate_max, 60.0))
    try:
        httpd = ThreadingHTTPServer((host, port), handler)
    except OSError as exc:
        print("gateway bind failed (%s:%d): %s" % (host, port, exc))
        return 1

    print("audit gateway listening on %s:%d (timeout_ms=%d, rate_max/min=%d) "
          "-- LOCAL, not enabled for remote" % (
              host, port, pipeline.timeout_ms, rate_max))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("shutdown")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())