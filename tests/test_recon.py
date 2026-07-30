"""
tests/test_recon.py
───────────────────
Tests for reconnaissance modules.
"""

import unittest
from unittest.mock import Mock, patch
from pathlib import Path

from modules.session import Session, SessionMode
from modules.recon.domain import DomainRecon
from modules.recon.subdomain import SubdomainRecon
from modules.recon.web import WebRecon
from modules.recon.cdn import CDNRecon
from modules.recon.cloud import CloudRecon
from modules.recon.social import SocialRecon
from modules.recon.cache import CacheRecon
from modules.recon.vuln_intel import VulnIntelRecon
from modules.recon.network import NetworkRecon
from modules.recon.web_deep import WebDeepRecon
from modules.recon.database import DatabaseRecon
from modules.recon.service import ServiceRecon
from modules.recon.cloud_deep import CloudDeepRecon
from modules.recon.vpn import VPNRecon
from modules.recon.auth import AuthRecon
from modules.recon.dev import DevRecon
from modules.recon.lateral import LateralRecon


class TestReconModules(unittest.TestCase):
    """Test reconnaissance modules."""

    def setUp(self):
        """Set up test session."""
        self.session = Session("test-target.com", SessionMode.FULL)
        self.logger = Mock()

    @patch("modules.recon.domain.get_stealth_engine")
    def test_domain_recon_init(self, mock_stealth):
        """Test domain recon initialization."""
        recon = DomainRecon(self.session, self.logger)
        self.assertIsNotNone(recon)
        self.assertEqual(recon.session, self.session)

    @patch("modules.recon.subdomain.get_stealth_engine")
    def test_subdomain_recon_init(self, mock_stealth):
        """Test subdomain recon initialization."""
        recon = SubdomainRecon(self.session, self.logger)
        self.assertIsNotNone(recon)
        self.assertEqual(recon.session, self.session)

    @patch("modules.recon.web.get_stealth_engine")
    def test_web_recon_init(self, mock_stealth):
        """Test web recon initialization."""
        recon = WebRecon(self.session, self.logger)
        self.assertIsNotNone(recon)
        self.assertEqual(recon.session, self.session)

    @patch("modules.recon.cdn.get_stealth_engine")
    def test_cdn_recon_init(self, mock_stealth):
        """Test CDN recon initialization."""
        recon = CDNRecon(self.session, self.logger)
        self.assertIsNotNone(recon)
        self.assertEqual(recon.session, self.session)

    @patch("modules.recon.cloud.get_stealth_engine")
    def test_cloud_recon_init(self, mock_stealth):
        """Test cloud recon initialization."""
        recon = CloudRecon(self.session, self.logger)
        self.assertIsNotNone(recon)
        self.assertEqual(recon.session, self.session)

    @patch("modules.recon.social.get_stealth_engine")
    def test_social_recon_init(self, mock_stealth):
        """Test social recon initialization."""
        recon = SocialRecon(self.session, self.logger)
        self.assertIsNotNone(recon)
        self.assertEqual(recon.session, self.session)

    @patch("modules.recon.cache.get_stealth_engine")
    def test_cache_recon_init(self, mock_stealth):
        """Test cache recon initialization."""
        recon = CacheRecon(self.session, self.logger)
        self.assertIsNotNone(recon)
        self.assertEqual(recon.session, self.session)

    @patch("modules.recon.vuln_intel.get_stealth_engine")
    def test_vuln_intel_recon_init(self, mock_stealth):
        """Test vuln intel recon initialization."""
        recon = VulnIntelRecon(self.session, self.logger)
        self.assertIsNotNone(recon)
        self.assertEqual(recon.session, self.session)

    @patch("modules.recon.network.get_stealth_engine")
    def test_network_recon_init(self, mock_stealth):
        """Test network recon initialization."""
        recon = NetworkRecon(self.session, self.logger)
        self.assertIsNotNone(recon)
        self.assertEqual(recon.session, self.session)

    @patch("modules.recon.web_deep.get_stealth_engine")
    def test_web_deep_recon_init(self, mock_stealth):
        """Test web deep recon initialization."""
        recon = WebDeepRecon(self.session, self.logger)
        self.assertIsNotNone(recon)
        self.assertEqual(recon.session, self.session)

    @patch("modules.recon.database.get_stealth_engine")
    def test_database_recon_init(self, mock_stealth):
        """Test database recon initialization."""
        recon = DatabaseRecon(self.session, self.logger)
        self.assertIsNotNone(recon)
        self.assertEqual(recon.session, self.session)

    @patch("modules.recon.service.get_stealth_engine")
    def test_service_recon_init(self, mock_stealth):
        """Test service recon initialization."""
        recon = ServiceRecon(self.session, self.logger)
        self.assertIsNotNone(recon)
        self.assertEqual(recon.session, self.session)

    @patch("modules.recon.cloud_deep.get_stealth_engine")
    def test_cloud_deep_recon_init(self, mock_stealth):
        """Test cloud deep recon initialization."""
        recon = CloudDeepRecon(self.session, self.logger)
        self.assertIsNotNone(recon)
        self.assertEqual(recon.session, self.session)

    @patch("modules.recon.vpn.get_stealth_engine")
    def test_vpn_recon_init(self, mock_stealth):
        """Test VPN recon initialization."""
        recon = VPNRecon(self.session, self.logger)
        self.assertIsNotNone(recon)
        self.assertEqual(recon.session, self.session)

    @patch("modules.recon.auth.get_stealth_engine")
    def test_auth_recon_init(self, mock_stealth):
        """Test auth recon initialization."""
        recon = AuthRecon(self.session, self.logger)
        self.assertIsNotNone(recon)
        self.assertEqual(recon.session, self.session)

    @patch("modules.recon.dev.get_stealth_engine")
    def test_dev_recon_init(self, mock_stealth):
        """Test dev recon initialization."""
        recon = DevRecon(self.session, self.logger)
        self.assertIsNotNone(recon)
        self.assertEqual(recon.session, self.session)

    @patch("modules.recon.lateral.get_stealth_engine")
    def test_lateral_recon_init(self, mock_stealth):
        """Test lateral recon initialization."""
        recon = LateralRecon(self.session, self.logger)
        self.assertIsNotNone(recon)
        self.assertEqual(recon.session, self.session)


if __name__ == "__main__":
    unittest.main()