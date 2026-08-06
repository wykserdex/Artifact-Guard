"""Unit tests for events and data models."""

import pytest
from uuid import UUID, uuid4
from datetime import datetime, timezone

from shared.events import (
    ArtifactType,
    SuspiciousArtifactSubmitted,
    Indicator,
    VerdictType,
    ArtifactAnalysisCompleted,
    AnalysisFailed,
)


class TestArtifactType:
    """Tests for ArtifactType enum."""

    def test_artifact_type_values(self):
        """Test artifact type enum values."""
        assert ArtifactType.URL.value == "url"
        assert ArtifactType.DOMAIN.value == "domain"
        assert ArtifactType.FILE.value == "file"
        assert ArtifactType.TEXT.value == "text"

    def test_artifact_type_from_string(self):
        """Test creating artifact type from string."""
        assert ArtifactType("url") == ArtifactType.URL
        assert ArtifactType("domain") == ArtifactType.DOMAIN


class TestSuspiciousArtifactSubmitted:
    """Tests for SuspiciousArtifactSubmitted event model."""

    def test_minimal_event_creation(self):
        """Test creating minimal event."""
        correlation_id = uuid4()
        
        event = SuspiciousArtifactSubmitted(
            correlation_id=correlation_id,
            artifact_type=ArtifactType.URL,
            value="https://example.com",
        )
        
        assert event.schema_version == 1
        assert isinstance(event.event_id, UUID)
        assert event.correlation_id == correlation_id
        assert event.created_at is not None
        assert event.source_system == "untilscam"
        assert event.source_chat_hash is None
        assert event.source_message_hash is None
        assert event.context_excerpt is None

    def test_full_event_creation(self):
        """Test creating event with all fields."""
        correlation_id = uuid4()
        created_at = datetime.now(timezone.utc)
        
        event = SuspiciousArtifactSubmitted(
            schema_version=1,
            correlation_id=correlation_id,
            created_at=created_at,
            artifact_type=ArtifactType.URL,
            value="https://example.com/phishing",
            source_system="untilscam",
            source_chat_hash="chat_hash_123",
            source_message_hash="msg_hash_456",
            context_excerpt="User sent suspicious link",
        )
        
        assert event.schema_version == 1
        assert event.artifact_type == ArtifactType.URL
        assert event.value == "https://example.com/phishing"
        assert event.source_chat_hash == "chat_hash_123"
        assert event.context_excerpt == "User sent suspicious link"

    def test_context_excerpt_max_length(self):
        """Test that context excerpt is limited to 1000 chars."""
        long_excerpt = "a" * 1001
        
        with pytest.raises(Exception):  # Pydantic validation error
            SuspiciousArtifactSubmitted(
                correlation_id=uuid4(),
                artifact_type=ArtifactType.TEXT,
                value="test",
                context_excerpt=long_excerpt,
            )

    def test_different_artifact_types(self):
        """Test event with different artifact types."""
        correlation_id = uuid4()
        
        url_event = SuspiciousArtifactSubmitted(
            correlation_id=correlation_id,
            artifact_type=ArtifactType.URL,
            value="https://example.com",
        )
        assert url_event.artifact_type == ArtifactType.URL
        
        domain_event = SuspiciousArtifactSubmitted(
            correlation_id=correlation_id,
            artifact_type=ArtifactType.DOMAIN,
            value="example.com",
        )
        assert domain_event.artifact_type == ArtifactType.DOMAIN
        
        file_event = SuspiciousArtifactSubmitted(
            correlation_id=correlation_id,
            artifact_type=ArtifactType.FILE,
            value="suspicious.exe",
        )
        assert file_event.artifact_type == ArtifactType.FILE


class TestIndicator:
    """Tests for Indicator model."""

    def test_minimal_indicator_creation(self):
        """Test creating minimal indicator."""
        indicator = Indicator(
            name="test_indicator",
            score=0.5,
            severity="medium",
            explanation="Test explanation",
        )
        
        assert indicator.name == "test_indicator"
        assert indicator.score == 0.5
        assert indicator.severity == "medium"
        assert indicator.explanation == "Test explanation"
        assert indicator.evidence_ids == []

    def test_indicator_with_evidence(self):
        """Test creating indicator with evidence IDs."""
        evidence_ids = [uuid4(), uuid4()]
        
        indicator = Indicator(
            name="credential_form",
            score=0.8,
            severity="high",
            explanation="Form detected",
            evidence_ids=evidence_ids,
        )
        
        assert len(indicator.evidence_ids) == 2
        assert indicator.evidence_ids == evidence_ids

    def test_score_bounds(self):
        """Test that score is bounded between 0 and 1."""
        # Valid scores
        indicator_low = Indicator(
            name="test", score=0.0, severity="low", explanation="Test"
        )
        indicator_high = Indicator(
            name="test", score=1.0, severity="high", explanation="Test"
        )
        
        assert indicator_low.score == 0.0
        assert indicator_high.score == 1.0
        
        # Invalid score should raise validation error
        with pytest.raises(Exception):
            Indicator(name="test", score=1.5, severity="high", explanation="Test")
        
        with pytest.raises(Exception):
            Indicator(name="test", score=-0.1, severity="low", explanation="Test")


class TestVerdictType:
    """Tests for VerdictType enum."""

    def test_verdict_type_values(self):
        """Test verdict type enum values."""
        assert VerdictType.ALLOW.value == "ALLOW"
        assert VerdictType.SUSPICIOUS.value == "SUSPICIOUS"
        assert VerdictType.HIGH_RISK.value == "HIGH_RISK"
        assert VerdictType.MANUAL_REVIEW.value == "MANUAL_REVIEW"
        assert VerdictType.PROCESSING_ERROR.value == "PROCESSING_ERROR"

    def test_verdict_type_from_string(self):
        """Test creating verdict type from string."""
        assert VerdictType("ALLOW") == VerdictType.ALLOW
        assert VerdictType("HIGH_RISK") == VerdictType.HIGH_RISK


class TestArtifactAnalysisCompleted:
    """Tests for ArtifactAnalysisCompleted event model."""

    def test_minimal_completion_event(self):
        """Test creating minimal completion event."""
        correlation_id = uuid4()
        analysis_id = uuid4()
        
        event = ArtifactAnalysisCompleted(
            correlation_id=correlation_id,
            analysis_id=analysis_id,
            verdict=VerdictType.ALLOW,
            risk_score=0.1,
        )
        
        assert event.schema_version == 1
        assert isinstance(event.event_id, UUID)
        assert event.correlation_id == correlation_id
        assert event.analysis_id == analysis_id
        assert event.verdict == VerdictType.ALLOW
        assert event.risk_score == 0.1
        assert event.indicators == []
        assert event.processing_time_ms is None
        assert event.error_message is None

    def test_completion_with_indicators(self):
        """Test completion event with indicators."""
        indicators = [
            Indicator(
                name="recent_domain",
                score=0.3,
                severity="medium",
                explanation="Domain registered recently",
            ),
        ]
        
        event = ArtifactAnalysisCompleted(
            correlation_id=uuid4(),
            analysis_id=uuid4(),
            verdict=VerdictType.SUSPICIOUS,
            risk_score=0.55,
            indicators=indicators,
            processing_time_ms=1500,
        )
        
        assert len(event.indicators) == 1
        assert event.processing_time_ms == 1500

    def test_completion_with_error(self):
        """Test completion event with error."""
        event = ArtifactAnalysisCompleted(
            correlation_id=uuid4(),
            analysis_id=uuid4(),
            verdict=VerdictType.PROCESSING_ERROR,
            risk_score=0.0,
            error_message="DNS resolution failed",
        )
        
        assert event.verdict == VerdictType.PROCESSING_ERROR
        assert event.error_message == "DNS resolution failed"

    def test_risk_score_bounds(self):
        """Test that risk score is bounded."""
        # Valid scores
        event_low = ArtifactAnalysisCompleted(
            correlation_id=uuid4(),
            analysis_id=uuid4(),
            verdict=VerdictType.ALLOW,
            risk_score=0.0,
        )
        event_high = ArtifactAnalysisCompleted(
            correlation_id=uuid4(),
            analysis_id=uuid4(),
            verdict=VerdictType.HIGH_RISK,
            risk_score=1.0,
        )
        
        assert event_low.risk_score == 0.0
        assert event_high.risk_score == 1.0


class TestAnalysisFailed:
    """Tests for AnalysisFailed event model."""

    def test_minimal_failure_event(self):
        """Test creating minimal failure event."""
        correlation_id = uuid4()
        analysis_id = uuid4()
        
        event = AnalysisFailed(
            correlation_id=correlation_id,
            analysis_id=analysis_id,
            error_type="DnsResolutionError",
            error_message="Failed to resolve hostname",
        )
        
        assert event.schema_version == 1
        assert isinstance(event.event_id, UUID)
        assert event.correlation_id == correlation_id
        assert event.analysis_id == analysis_id
        assert event.error_type == "DnsResolutionError"
        assert event.error_message == "Failed to resolve hostname"
        assert event.retryable is True

    def test_non_retryable_failure(self):
        """Test creating non-retryable failure event."""
        event = AnalysisFailed(
            correlation_id=uuid4(),
            error_type="InvalidArtifactError",
            error_message="Artifact format is invalid",
            retryable=False,
        )
        
        assert event.retryable is False
        assert event.analysis_id is None

    def test_failure_without_analysis_id(self):
        """Test failure event before analysis started."""
        event = AnalysisFailed(
            correlation_id=uuid4(),
            error_type="SubmissionError",
            error_message="Failed to submit artifact",
        )
        
        assert event.analysis_id is None
        assert event.retryable is True  # Default
