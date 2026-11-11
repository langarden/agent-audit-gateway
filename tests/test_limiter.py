# -*- coding: utf-8 -*-
import time
import unittest

from aag.limiter import RateLimiter


class LimiterTests(unittest.TestCase):
    def test_allow_within_limit(self):
        lim = RateLimiter(limit=3, window_seconds=60.0)
        self.assertTrue(lim.allow("ip-1"))
        self.assertTrue(lim.allow("ip-1"))
        self.assertTrue(lim.allow("ip-1"))

    def test_deny_over_limit(self):
        lim = RateLimiter(limit=2, window_seconds=60.0)
        self.assertTrue(lim.allow("ip-1"))
        self.assertTrue(lim.allow("ip-1"))
        self.assertFalse(lim.allow("ip-1"))

    def test_independent_keys(self):
        lim = RateLimiter(limit=1, window_seconds=60.0)
        self.assertTrue(lim.allow("a"))
        self.assertFalse(lim.allow("a"))
        self.assertTrue(lim.allow("b"))

    def test_window_expires(self):
        lim = RateLimiter(limit=1, window_seconds=0.05)
        self.assertTrue(lim.allow("ip-1"))
        self.assertFalse(lim.allow("ip-1"))
        time.sleep(0.08)
        self.assertTrue(lim.allow("ip-1"))

    def test_reset(self):
        lim = RateLimiter(limit=1, window_seconds=60.0)
        self.assertTrue(lim.allow("a"))
        self.assertFalse(lim.allow("a"))
        lim.reset()
        self.assertTrue(lim.allow("a"))

    def test_limit_must_be_positive(self):
        with self.assertRaises(ValueError):
            RateLimiter(limit=0)


if __name__ == "__main__":
    unittest.main()