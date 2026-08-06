"""Tests for passive analyzers."""

import pytest
from unittest.mock import patch, AsyncMock
from uuid import uuid4

from analysis.passive.dns import DnsAnalyzer, resolve_dns
from analysis.passive.homoglyphs import HomoglyphAnalyzer, HOMOGLYPHS, detect_homoglyphs, normalize_domain, is_mixed_script
from analysis.passive.reputation import ReputationAnalyzer, check_domain_blocklist, check_ip_reputation
from analysis.passive.rdap import RdapAnalyzer
from domain.analysis import AnalysisContext
from shared.events import ArtifactType


class TestDnsAnalyzer:
    """Tests for DNS analyzer."""

    @pytest.mark.asyncio
    async def test_analyze_no_hostname(self):
        """Test analyze with no hostname."""
        analyzer = DnsAnalyzer()
        context = AnalysisContext(
            artifact_type=ArtifactType.URL,
            artifact_value="http://example.com",
        )
        context._hostname = None
        
        indicators = await analyzer.analyze(context)
        
        assert len(indicators) == 0

    @pytest.mark.asyncio
    async def test_analyze_suspicious_tld(self):
        """Test detection of suspicious TLD."""
        analyzer = DnsAnalyzer()
        context = AnalysisContext(
            artifact_type=ArtifactType.URL,
            artifact_value="http://example.xyz",
        )
        
        with patch('analysis.passive.dns.resolve_dns') as mock_resolve:
            mock_resolve.return_value.a_records = ["1.2.3.4"]
            mock_resolve.return_value.txt_records = ["v=spf1 include:_spf.google.com ~all"]
            
            indicators = await analyzer.analyze(context)
        
        suspicious_tld = [i for i in indicators if i.name == "suspicious_tld"]
        assert len(suspicious_tld) > 0
        assert ".xyz" in suspicious_tld[0].explanation


class TestHomoglyphAnalyzer:
    """Tests for homoglyph analyzer."""

    def test_detect_homoglyphs_cyrillic(self):
        """Test detection of Cyrillic homoglyphs."""
        # Cyrillic 'а' (U+0430) instead of Latin 'a'
        findings = detect_homoglyphs("exаmple")  # Contains Cyrillic 'а'
        
        assert len(findings) > 0

    def test_normalize_domain(self):
        """Test domain normalization."""
        normalized = normalize_domain("exаmple")  # Cyrillic 'а'
        assert normalized == "example"

    def test_is_mixed_script_ascii(self):
        """Test mixed script detection - ASCII only."""
        # Pure ASCII should not be mixed script
        assert not is_mixed_script("example")

    @pytest.mark.asyncio
    async def test_analyze_homoglyph_detection(self):
        """Test homoglyph detection in analyzer."""
        analyzer = HomoglyphAnalyzer()
        context = AnalysisContext(
            artifact_type=ArtifactType.URL,
            artifact_value="http://exаmple.com",  # Cyrillic 'а'
        )
        
        indicators = await analyzer.analyze(context)
        
        homoglyph_indicators = [i for i in indicators if i.name == "homoglyph_domain"]
        assert len(homoglyph_indicators) > 0
        assert homoglyph_indicators[0].score >= 0.7


class TestReputationAnalyzer:
    """Tests for reputation analyzer."""

    def test_check_domain_blocklist(self):
        """Test blocklist checking."""
        assert check_domain_blocklist("example-phishing.com")
        assert not check_domain_blocklist("google.com")

    def test_check_ip_reputation(self):
        """Test IP reputation checking."""
        # Known malicious range
        assert check_ip_reputation("185.220.101.50")
        # Clean IP
        assert not check_ip_reputation("8.8.8.8")

    @pytest.mark.asyncio
    async def test_analyze_known_malicious(self):
        """Test detection of known malicious domain."""
        analyzer = ReputationAnalyzer()
        context = AnalysisContext(
            artifact_type=ArtifactType.URL,
            artifact_value="http://example-phishing.com",
        )
        
        indicators = await analyzer.analyze(context)
        
        malicious_indicators = [i for i in indicators if i.name == "known_malicious_domain"]
        assert len(malicious_indicators) > 0
        assert malicious_indicators[0].score >= 0.9


class TestRdapAnalyzer:
    """Tests for RDAP analyzer."""

    @pytest.mark.asyncio
    async def test_analyze_no_hostname(self):
        """Test analyze with no hostname."""
        analyzer = RdapAnalyzer()
        context = AnalysisContext(
            artifact_type=ArtifactType.URL,
            artifact_value="http://example.com",
        )
        context._hostname = None
        
        indicators = await analyzer.analyze(context)
        
        assert len(indicators) == 0

    @pytest.mark.asyncio
    async def test_analyze_lookup_failed(self):
        """Test RDAP lookup failure handling."""
        analyzer = RdapAnalyzer()
        context = AnalysisContext(
            artifact_type=ArtifactType.URL,
            artifact_value="http://nonexistent-domain-12345.com",
        )
        
        with patch('analysis.passive.rdap.lookup_rdap', new_callable=AsyncMock) as mock_lookup:
            mock_lookup.return_value = None
            
            indicators = await analyzer.analyze(context)
        
        failed_indicators = [i for i in indicators if i.name == "rdap_lookup_failed"]
        assert len(failed_indicators) > 0
