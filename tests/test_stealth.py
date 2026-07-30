"""
tests/test_stealth.py
─────────────────────
Tests for stealth engine.
"""

import unittest
from unittest.mock import Mock, patch
from pathlib import Path

from modules.stealth import StealthEngine, StealthConfig, ScanMode, get_stealth_engine


class TestStealthEngine(unittest.TestCase):
    """Test stealth engine."""

    def setUp(self):
        """Set up test configuration."""
        self.config = StealthConfig()
        self.config.enabled = True
        self.config.rate_limit = 2.0
        self.config.jitter = 0.5
        self.config.scan_mode = ScanMode.LOW
        self.logger = Mock()

    def test_stealth_engine_init(self):
        """Test stealth engine initialization."""
        engine = StealthEngine(self.logger)
        self.assertIsNotNone(engine)
        self.assertTrue(engine.config.enabled)

    def test_stealth_engine_config_override(self):
        """Test stealth engine with custom config."""
        engine = StealthEngine(self.logger, self.config)
        self.assertEqual(engine.config.rate_limit, 2.0)
        self.assertEqual(engine.config.scan_mode, ScanMode.LOW)

    @patch("modules.stealth.time.time")
    def test_stealth_delay(self, mock_time):
        """Test stealth delay."""
        mock_time.return_value = 0.0
        engine = StealthEngine(self.logger, self.config)
        # Should not raise exception
        engine._delay()

    def test_stealth_get_user_agent(self):
        """Test User-Agent rotation."""
        engine = StealthEngine(self.logger, self.config)
        ua1 = engine.get_user_agent()
        ua2 = engine.get_user_agent()
        self.assertIsNotNone(ua1)
        self.assertIsInstance(ua1, str)

    def test_stealth_get_headers(self):
        """Test header generation."""
        engine = StealthEngine(self.logger, self.config)
        headers = engine.get_headers()
        self.assertIn("User-Agent", headers)
        self.assertIn("Accept", headers)
        self.assertIn("Accept-Language", headers)

    @patch("modules.stealth.urllib.request.urlopen")
    def test_stealth_request(self, mock_urlopen):
        """Test stealth request."""
        mock_response = Mock()
        mock_response.status = 200
        mock_response.headers = {"Content-Type": "text/html"}
        mock_response.read.return_value = b"<html>test</html>"
        mock_urlopen.return_value.__enter__.return_value = mock_response

        engine = StealthEngine(self.logger, self.config)
        status, headers, content = engine.request("https://example.com")

        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "text/html")
        self.assertEqual(content, "<html>test</html>")

    def test_stealth_captcha_detection(self):
        """Test CAPTCHA detection."""
        engine = StealthEngine(self.logger, self.config)

        # Should detect CAPTCHA
        content = "Please verify you are human by completing the captcha"
        self.assertTrue(engine.check_captcha(content))

        # Should not detect CAPTCHA
        content = "Welcome to the website"
        self.assertFalse(engine.check_captcha(content))

    def test_stealth_rate_limit_detection(self):
        """Test rate limit detection."""
        engine = StealthEngine(self.logger, self.config)

        # 429 status code
        rate_limited, retry = engine.check_rate_limit(429, {"retry-after": "60"})
        self.assertTrue(rate_limited)
        self.assertEqual(retry, 60)

        # 200 status code
        rate_limited, retry = engine.check_rate_limit(200, {})
        self.assertFalse(rate_limited)

    def test_stealth_pause_resume(self):
        """Test pause and resume."""
        engine = StealthEngine(self.logger, self.config)
        self.assertFalse(engine._paused)

        engine.pause()
        self.assertTrue(engine._paused)

        engine.resume()
        self.assertFalse(engine._paused)

    def test_stealth_reset(self):
        """Test reset."""
        engine = StealthEngine(self.logger, self.config)
        engine._request_count = 100
        engine._error_count = 5

        engine.reset()
        self.assertEqual(engine._request_count, 0)
        self.assertEqual(engine._error_count, 0)

    def test_get_global_stealth_engine(self):
        """Test global stealth engine singleton."""
        engine1 = get_stealth_engine()
        engine2 = get_stealth_engine()
        self.assertIs(engine1, engine2)

    def test_reset_global_stealth_engine(self):
        """Test resetting global stealth engine."""
        from modules.stealth import reset_stealth_engine, _stealth_engine
        _stealth_engine = None
        engine = get_stealth_engine()
        self.assertIsNotNone(engine)
        reset_stealth_engine()
        self.assertIsNone(_stealth_engine)


if __name__ == "__main__":
    unittest.main()