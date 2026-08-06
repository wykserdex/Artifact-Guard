"""Unit tests for verdict determination."""

import pytest

from domain.verdict import (
    determine_verdict,
    should_block,
    should_alert,
    VerdictDecision,
)
from shared.events import VerdictType


class TestDetermineVerdict:
    """Tests for verdict determination based on risk score."""

    def test_high_risk_threshold(self):
        """Test HIGH_RISK verdict at threshold."""
        decision = determine_verdict(0.85)
        
        assert decision.verdict == VerdictType.HIGH_RISK
        assert decision.risk_score == 0.85
        assert "High risk" in decision.explanation
        assert decision.auto_action_allowed is True
        assert decision.requires_manual_review is False

    def test_high_risk_above_threshold(self):
        """Test HIGH_RISK verdict above threshold."""
        decision = determine_verdict(0.95)
        
        assert decision.verdict == VerdictType.HIGH_RISK
        assert decision.auto_action_allowed is True

    def test_suspicious_threshold(self):
        """Test SUSPICIOUS verdict at threshold."""
        decision = determine_verdict(0.55)
        
        assert decision.verdict == VerdictType.SUSPICIOUS
        assert decision.risk_score == 0.55
        assert "Suspicious" in decision.explanation
        assert decision.auto_action_allowed is False
        assert decision.requires_manual_review is True

    def test_suspicious_range(self):
        """Test SUSPICIOUS verdict in range."""
        decision = determine_verdict(0.70)
        
        assert decision.verdict == VerdictType.SUSPICIOUS
        assert decision.auto_action_allowed is False

    def test_manual_review_threshold(self):
        """Test MANUAL_REVIEW verdict at threshold."""
        decision = determine_verdict(0.30)
        
        assert decision.verdict == VerdictType.MANUAL_REVIEW
        assert decision.risk_score == 0.30
        assert "Manual" in decision.explanation or "manual" in decision.explanation.lower()
        assert decision.auto_action_allowed is False
        assert decision.requires_manual_review is True

    def test_manual_review_range(self):
        """Test MANUAL_REVIEW verdict in range."""
        decision = determine_verdict(0.45)
        
        assert decision.verdict == VerdictType.MANUAL_REVIEW

    def test_allow_below_threshold(self):
        """Test ALLOW verdict below threshold."""
        decision = determine_verdict(0.29)
        
        assert decision.verdict == VerdictType.ALLOW
        assert decision.risk_score == 0.29
        assert decision.auto_action_allowed is True
        assert decision.requires_manual_review is False

    def test_allow_zero_score(self):
        """Test ALLOW verdict with zero score."""
        decision = determine_verdict(0.0)
        
        assert decision.verdict == VerdictType.ALLOW
        assert "No significant risk" in decision.explanation

    def test_allow_very_low_score(self):
        """Test ALLOW verdict with very low score."""
        decision = determine_verdict(0.10)
        
        assert decision.verdict == VerdictType.ALLOW

    def test_perfect_score(self):
        """Test verdict with perfect risk score."""
        decision = determine_verdict(1.0)
        
        assert decision.verdict == VerdictType.HIGH_RISK
        assert decision.risk_score == 1.0


class TestShouldBlock:
    """Tests for automatic blocking decision."""

    def test_block_high_risk(self):
        """Test that HIGH_RISK allows blocking."""
        decision = determine_verdict(0.90)
        
        assert should_block(decision) is True

    def test_no_block_suspicious(self):
        """Test that SUSPICIOUS does not allow automatic blocking."""
        decision = determine_verdict(0.60)
        
        assert should_block(decision) is False

    def test_no_block_manual_review(self):
        """Test that MANUAL_REVIEW does not allow blocking."""
        decision = determine_verdict(0.40)
        
        assert should_block(decision) is False

    def test_no_block_allow(self):
        """Test that ALLOW does not allow blocking."""
        decision = determine_verdict(0.10)
        
        assert should_block(decision) is False


class TestShouldAlert:
    """Tests for alert decision."""

    def test_alert_high_risk(self):
        """Test that HIGH_RISK triggers alert."""
        decision = determine_verdict(0.90)
        
        assert should_alert(decision) is True

    def test_alert_suspicious(self):
        """Test that SUSPICIOUS triggers alert."""
        decision = determine_verdict(0.60)
        
        assert should_alert(decision) is True

    def test_no_alert_manual_review(self):
        """Test that MANUAL_REVIEW does not trigger alert."""
        decision = determine_verdict(0.40)
        
        assert should_alert(decision) is False

    def test_no_alert_allow(self):
        """Test that ALLOW does not trigger alert."""
        decision = determine_verdict(0.10)
        
        assert should_alert(decision) is False


class TestVerdictDecision:
    """Tests for VerdictDecision dataclass."""

    def test_decision_creation(self):
        """Test creating a verdict decision."""
        decision = VerdictDecision(
            verdict=VerdictType.HIGH_RISK,
            risk_score=0.85,
            explanation="Test explanation",
            requires_manual_review=False,
            auto_action_allowed=True,
        )
        
        assert decision.verdict == VerdictType.HIGH_RISK
        assert decision.risk_score == 0.85
        assert decision.explanation == "Test explanation"
        assert decision.requires_manual_review is False
        assert decision.auto_action_allowed is True

    def test_decision_defaults(self):
        """Test default values in verdict decision."""
        decision = VerdictDecision(
            verdict=VerdictType.SUSPICIOUS,
            risk_score=0.55,
            explanation="Test",
        )
        
        assert decision.requires_manual_review is False
        assert decision.auto_action_allowed is True


class TestVerdictBoundaries:
    """Tests for boundary conditions in verdict determination."""

    def test_boundary_high_risk_exactly(self):
        """Test verdict at exact HIGH_RISK boundary."""
        decision = determine_verdict(0.85)
        assert decision.verdict == VerdictType.HIGH_RISK

    def test_boundary_just_below_high_risk(self):
        """Test verdict just below HIGH_RISK boundary."""
        decision = determine_verdict(0.849)
        assert decision.verdict == VerdictType.SUSPICIOUS

    def test_boundary_suspicious_exactly(self):
        """Test verdict at exact SUSPICIOUS boundary."""
        decision = determine_verdict(0.55)
        assert decision.verdict == VerdictType.SUSPICIOUS

    def test_boundary_just_below_suspicious(self):
        """Test verdict just below SUSPICIOUS boundary."""
        decision = determine_verdict(0.549)
        assert decision.verdict == VerdictType.MANUAL_REVIEW

    def test_boundary_manual_review_exactly(self):
        """Test verdict at exact MANUAL_REVIEW boundary."""
        decision = determine_verdict(0.30)
        assert decision.verdict == VerdictType.MANUAL_REVIEW

    def test_boundary_just_below_manual_review(self):
        """Test verdict just below MANUAL_REVIEW boundary."""
        decision = determine_verdict(0.299)
        assert decision.verdict == VerdictType.ALLOW
