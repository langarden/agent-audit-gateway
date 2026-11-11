# -*- coding: utf-8 -*-
import unittest

from aag.auth import CallerRegistry, hash_credential

REG = {
    "callers": [
        {"caller_id": "agent-alpha", "credential_hash": "sha256:" + hash_credential("tok-a"),
         "status": "active", "capabilities": ["data.lookup"], "max_action": "read", "max_data_class": "public"},
        {"caller_id": "agent-disabled", "credential_hash": "sha256:" + hash_credential("tok-d"),
         "status": "disabled", "capabilities": ["data.lookup"], "max_action": "read", "max_data_class": "public"},
    ]
}


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.reg = CallerRegistry.from_dict(REG)

    def test_hash_stable(self):
        self.assertEqual(hash_credential("abc"), hash_credential("abc"))
        self.assertNotEqual(hash_credential("abc"), hash_credential("abd"))

    def test_authenticate_active_caller(self):
        self.assertEqual(self.reg.authenticate("tok-a"), "agent-alpha")

    def test_authenticate_wrong_token(self):
        self.assertIsNone(self.reg.authenticate("wrong"))

    def test_authenticate_disabled_denied(self):
        self.assertIsNone(self.reg.authenticate("tok-d"))

    def test_authenticate_empty_token(self):
        self.assertIsNone(self.reg.authenticate(""))
        self.assertIsNone(self.reg.authenticate(None))

    def test_missing_file_fail_closed(self):
        reg = CallerRegistry.from_file("/definitely/missing/registry.json")
        self.assertEqual(reg.authenticate("anything"), None)

    def test_caller_hashes_only_active(self):
        hashes = self.reg.caller_hashes()
        self.assertIn("agent-alpha", hashes)
        self.assertNotIn("agent-disabled", hashes)


if __name__ == "__main__":
    unittest.main()