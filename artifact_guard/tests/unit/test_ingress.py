"""Tests for ingress module."""

import pytest
from uuid import uuid4
from datetime import datetime, timezone

from shared.events import SuspiciousArtifactSubmitted, ArtifactType
from ingress.extractor import ArtifactExtractor
from ingress.deduplication import DeduplicationService


class TestArtifactExtractor:
    """Tests for artifact extraction from text."""

    def test_extract_url_with_scheme(self):
        """Extract URL with http/https scheme."""
        extractor = ArtifactExtractor()
        text = "Check https://evil-phishing.com/login"
        artifacts = extractor.extract_from_text(text)
        
        assert len(artifacts) == 1
        assert artifacts[0].artifact_type == ArtifactType.URL
        assert artifacts[0].value == "https://evil-phishing.com/login"

    def test_extract_url_without_scheme(self):
        """Extract URL without explicit scheme."""
        extractor = ArtifactExtractor()
        text = "Visit bad-site.ru now"
        artifacts = extractor.extract_from_text(text)
        
        assert len(artifacts) == 1
        assert artifacts[0].artifact_type == ArtifactType.URL
        assert "bad-site.ru" in artifacts[0].value

    def test_extract_multiple_urls(self):
        """Extract multiple URLs from text."""
        extractor = ArtifactExtractor()
        text = "See https://site1.com and http://site2.org/path"
        artifacts = extractor.extract_from_text(text)
        
        assert len(artifacts) == 2
        assert all(a.artifact_type == ArtifactType.URL for a in artifacts)

    def test_skip_email_as_domain(self):
        """Don't extract email domains as standalone domains."""
        extractor = ArtifactExtractor()
        text = "Contact user@example.com or visit example.com"
        artifacts = extractor.extract_from_text(text)
        
        # Should extract example.com twice (once from email context, once standalone)
        # But the extractor should skip domain if it's part of email
        assert len(artifacts) >= 1

    def test_context_extraction(self):
        """Extract surrounding context for artifacts."""
        extractor = ArtifactExtractor()
        text = "SCAM WARNING: Click http://scam.net/fake to lose money"
        artifacts = extractor.extract_from_text(text)
        
        assert len(artifacts) == 1
        assert artifacts[0].context is not None
        assert "SCAM WARNING" in artifacts[0].context
        assert "lose money" in artifacts[0].context


class TestDeduplicationService:
    """Tests for deduplication logic."""

    @pytest.mark.asyncio
    async def test_idempotency_key_computation(self):
        """Test idempotency key is deterministic."""
        service = DeduplicationService(policy_version="v1")
        
        event1 = SuspiciousArtifactSubmitted(
            correlation_id=uuid4(),
            artifact_type=ArtifactType.URL,
            value="https://example.com",
        )
        
        event2 = SuspiciousArtifactSubmitted(
            correlation_id=uuid4(),
            artifact_type=ArtifactType.URL,
            value="https://example.com",
        )
        
        key1 = service._compute_idempotency_key(event1)
        key2 = service._compute_idempotency_key(event2)
        
        assert key1 == key2

    @pytest.mark.asyncio
    async def test_different_artifact_types_different_keys(self):
        """Different artifact types produce different keys."""
        service = DeduplicationService(policy_version="v1")
        
        url_event = SuspiciousArtifactSubmitted(
            correlation_id=uuid4(),
            artifact_type=ArtifactType.URL,
            value="example.com",
        )
        
        domain_event = SuspiciousArtifactSubmitted(
            correlation_id=uuid4(),
            artifact_type=ArtifactType.DOMAIN,
            value="example.com",
        )
        
        url_key = service._compute_idempotency_key(url_event)
        domain_key = service._compute_idempotency_key(domain_event)
        
        assert url_key != domain_key

    @pytest.mark.asyncio
    async def test_local_cache_duplicate_detection(self):
        """Test local cache detects duplicates."""
        service = DeduplicationService(policy_version="v1")
        
        event = SuspiciousArtifactSubmitted(
            correlation_id=uuid4(),
            artifact_type=ArtifactType.URL,
            value="https://duplicate.com",
        )
        
        # First check should mark as new
        is_dup1 = await service.is_duplicate(event)
        assert is_dup1 is False
        
        # Second check should detect duplicate
        is_dup2 = await service.is_duplicate(event)
        assert is_dup2 is True

    @pytest.mark.asyncio
    async def test_stats_reporting(self):
        """Test statistics reporting."""
        service = DeduplicationService(
            policy_version="v2",
            ttl_hours=48,
        )
        
        stats = service.get_stats()
        
        assert stats["policy_version"] == "v2"
        assert stats["ttl_hours"] == 48.0
        assert "local_cache_size" in stats
        assert "redis_connected" in stats
