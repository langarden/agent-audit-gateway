# -*- coding: utf-8 -*-
"""Bearer auth against a caller registry of sha256 hashes (fail-closed)."""
import hashlib
import hmac
import json
import os


def hash_credential(credential: str) -> str:
    """Storage form of a bearer credential: sha256 hex. Never store plaintext."""
    return hashlib.sha256(credential.encode("utf-8")).hexdigest()


def _normalize(stored: str) -> str:
    """Strip an optional 'sha256:' prefix from a stored hash."""
    return stored.split(":", 1)[-1] if ":" in stored else stored


def _load_callers(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh).get("callers", [])


class CallerRegistry:
    """Registry of caller_id -> credential_hash (sha256 only). Fail-closed."""

    def __init__(self, callers=None):
        self.callers = list(callers or [])

    @classmethod
    def from_file(cls, path):
        if not os.path.exists(path):
            return cls([])
        return cls(_load_callers(path))

    @classmethod
    def from_dict(cls, data):
        return cls(data.get("callers", []))

    def authenticate(self, token: str) -> str | None:
        """Return caller_id if token matches an active caller's hash.

        Any problem (missing token, unknown caller, disabled status, missing
        registry, load failure) resolves to None -> caller denied.
        """
        if not token:
            return None
        given = hash_credential(token)
        for entry in self.callers:
            if not isinstance(entry, dict) or entry.get("status") != "active":
                continue
            stored = _normalize(entry.get("credential_hash", ""))
            if hmac.compare_digest(given, stored):
                return entry.get("caller_id")
        return None

    def caller_info(self, caller_id: str) -> dict | None:
        for entry in self.callers:
            if entry.get("caller_id") == caller_id:
                return entry
        return None

    def caller_hashes(self) -> dict:
        """caller_id -> credential_hash (used to seed the guard registry)."""
        out = {}
        for entry in self.callers:
            if entry.get("status") == "active":
                out[entry["caller_id"]] = _normalize(entry.get("credential_hash", ""))
        return out