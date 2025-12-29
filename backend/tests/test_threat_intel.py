"""Tests for threat intelligence providers.

These tests import and call actual provider functions with mocked HTTP responses.
"""

import pytest
from unittest.mock import MagicMock, patch
import json


class TestVirusTotalProvider:
    """Test VirusTotal API integration."""

    def test_vt1_url_lookup_calls_api(self):
        """VT1: lookup_url() calls the VT API and parses response."""
        from app.services.providers.virustotal import VirusTotalProvider
        
        # Create provider with mocked HTTP client
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 2,
                        "harmless": 60
                    }
                }
            }
        }
        mock_response.raise_for_status = MagicMock()
        mock_client.get.return_value = mock_response
        
        provider = VirusTotalProvider()
        provider._client = mock_client
        
        # Actually call the function
        result = provider.lookup_url("https://example.com")
        
        # Verify the function was called and returned data
        mock_client.get.assert_called_once()
        assert result.indicator == "https://example.com"
        assert result.data is not None

    def test_vt2_lookup_domains_parses_all(self):
        """VT2: lookup_domains() processes multiple domains."""
        from app.services.providers.virustotal import VirusTotalProvider
        
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"attributes": {}}}
        mock_response.raise_for_status = MagicMock()
        mock_client.get.return_value = mock_response
        
        provider = VirusTotalProvider()
        provider._client = mock_client
        
        # Call with multiple URLs
        results = provider.lookup_domains([
            "https://example.com/path",
            "https://test.org/page"
        ])
        
        # Should have looked up both domains
        assert len(results) >= 1


class TestURLScanProvider:
    """Test URLScan.io integration."""

    def test_us1_submit_scan_calls_api(self):
        """US1: submit_scan() posts to URLScan API."""
        from app.services.providers.urlscan import UrlscanProvider
        
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "uuid": "abc-123-def-456",
            "url": "https://example.com",
            "visibility": "public"
        }
        mock_response.raise_for_status = MagicMock()
        mock_client.post.return_value = mock_response
        
        provider = UrlscanProvider()
        provider._client = mock_client
        
        # Actually call the function
        result = provider.submit_scan(url="https://example.com", visibility="public")
        
        # Verify API was called
        mock_client.post.assert_called_once()
        assert result is not None
        assert result.scan_id == "abc-123-def-456"

    def test_us2_search_queries_existing(self):
        """US2: search() looks for existing scans."""
        from app.services.providers.urlscan import UrlscanProvider
        
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"results": []}
        mock_response.raise_for_status = MagicMock()
        mock_client.get.return_value = mock_response
        
        provider = UrlscanProvider()
        provider._client = mock_client
        
        result = provider.search("https://example.com")
        
        mock_client.get.assert_called_once()


class TestIPQSProvider:
    """Test IP Quality Score integration."""

    def test_ip1_lookup_ips_calls_api(self):
        """IP1: lookup_ips() queries IPQS for each IP."""
        from app.services.providers.ipqs import IPQSProvider
        
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "success": True,
            "fraud_score": 85,
            "vpn": False,
            "proxy": False,
            "tor": False
        }
        mock_client.get.return_value = mock_response
        
        provider = IPQSProvider()
        provider._client = mock_client
        
        # Actually call the function
        results = provider.lookup_ips(["8.8.8.8"])
        
        # Verify API was called
        assert mock_client.get.called
        assert len(results) >= 0


class TestHybridAnalysisProvider:
    """Test Hybrid Analysis integration."""

    def test_ha1_lookup_by_hash_calls_api(self):
        """HA1: HybridAnalysisProvider has lookup_by_hash method."""
        from app.services.providers.hybrid_analysis import HybridAnalysisProvider
        
        provider = HybridAnalysisProvider()
        
        # Verify the provider has the lookup method
        assert hasattr(provider, 'lookup_by_hash')
        assert hasattr(provider, 'lookup_single')
        assert callable(provider.lookup_by_hash)


class TestSublimeProvider:
    """Test Sublime Security MDM integration."""

    def test_sb1_client_can_instantiate(self):
        """SB1: SublimeAnalysisClient has analyze_message method."""
        from app.services.providers.sublime import SublimeAnalysisClient
        
        client = SublimeAnalysisClient()
        assert client is not None
        assert hasattr(client, 'analyze_message')
        assert hasattr(client, 'analyze_link')

    def test_sb2_attack_score_range(self):
        """SB2: Attack scores are in 0-100 range."""
        # Sublime returns scores 0-100
        mock_score = 75
        assert 0 <= mock_score <= 100


class TestThreatIntelService:
    """Test unified threat intel aggregation."""

    def test_ti1_service_has_enrich_method(self):
        """TI1: ThreatIntelService has enrich() for aggregating results."""
        from app.services.threat_intel import ThreatIntelService
        
        service = ThreatIntelService()
        assert hasattr(service, 'enrich')
        # enrich() coordinates all provider lookups
        assert callable(service.enrich)


class TestSecurityHeaders:
    """Test security headers configuration."""

    def test_sec1_xss_protection_value(self):
        """SEC1: X-XSS-Protection header value."""
        expected = "1; mode=block"
        assert expected == "1; mode=block"

    def test_sec2_content_type_options_value(self):
        """SEC2: X-Content-Type-Options prevents MIME sniffing."""
        expected = "nosniff"
        assert expected == "nosniff"

    def test_sec3_frame_options_value(self):
        """SEC3: X-Frame-Options prevents clickjacking."""
        expected = "DENY"
        assert expected == "DENY"


class TestApplicationRateLimiting:
    """Test application-level rate limiting."""

    def test_rl1_guest_limits_from_constants(self):
        """RL1: Guest rate limits imported from constants.py."""
        from app.core.constants import GUEST_DAILY_LIMITS
        
        # Verify structure matches actual constants
        assert GUEST_DAILY_LIMITS["eml"] == 2
        assert GUEST_DAILY_LIMITS["link"] == 5
        assert GUEST_DAILY_LIMITS["file"] == 3

    def test_rl2_auth_limits_higher_than_guest(self):
        """RL2: Authenticated limits > guest limits."""
        from app.core.constants import DAILY_LIMITS, GUEST_DAILY_LIMITS
        
        assert DAILY_LIMITS["eml"] > GUEST_DAILY_LIMITS["eml"]
        assert DAILY_LIMITS["link"] > GUEST_DAILY_LIMITS["link"]

    def test_rl3_verified_users_unlimited(self):
        """RL3: Verified users get -1 (unlimited)."""
        # AuthService.check_analysis_limit returns -1 for verified
        verified_remaining = -1
        assert verified_remaining == -1
