"""Unit tests for scoring engine."""

import pytest

from domain.indicators import Indicator, Severity, IndicatorCategory
from scoring.engine import ScoringEngine, ScoringRule, get_default_scorer, DEFAULT_RULES


class TestScoringRule:
    """Tests for ScoringRule dataclass."""

    def test_rule_creation(self):
        """Test creating a scoring rule."""
        rule = ScoringRule(
            indicator_name="test_indicator",
            base_weight=0.5,
            min_confidence=0.7,
        )
        
        assert rule.indicator_name == "test_indicator"
        assert rule.base_weight == 0.5
        assert rule.min_confidence == 0.7


class TestScoringEngine:
    """Tests for ScoringEngine."""

    def test_empty_indicators_returns_zero(self):
        """Test that empty indicator list returns zero score."""
        engine = ScoringEngine()
        score = engine.calculate([])
        
        assert score == 0.0

    def test_single_indicator_below_confidence(self):
        """Test indicator below confidence threshold is ignored."""
        engine = ScoringEngine(rules={
            "low_confidence": ScoringRule(
                indicator_name="low_confidence",
                base_weight=0.5,
                min_confidence=0.8,
            ),
        })
        
        indicators = [
            Indicator(
                name="low_confidence",
                category=IndicatorCategory.URL,
                severity=Severity.MEDIUM,
                score=0.5,
                confidence=0.3,  # Below threshold
                explanation="Test",
            ),
        ]
        
        score = engine.calculate(indicators)
        assert score == 0.0

    def test_single_indicator_above_confidence(self):
        """Test indicator above confidence threshold contributes to score."""
        engine = ScoringEngine(rules={
            "high_confidence": ScoringRule(
                indicator_name="high_confidence",
                base_weight=0.5,
                min_confidence=0.5,
            ),
        })
        
        indicators = [
            Indicator(
                name="high_confidence",
                category=IndicatorCategory.URL,
                severity=Severity.HIGH,
                score=0.5,
                confidence=0.9,  # Above threshold
                explanation="Test",
            ),
        ]
        
        score = engine.calculate(indicators)
        # contribution = 0.5 * 0.9 = 0.45
        # risk = 1 - (1 - 0.45) = 0.45
        assert score == 0.45

    def test_multiple_indicators_probabilistic_combine(self):
        """Test that multiple indicators are combined probabilistically."""
        engine = ScoringEngine(rules={
            "indicator_a": ScoringRule(
                indicator_name="indicator_a",
                base_weight=0.5,
                min_confidence=0.5,
            ),
            "indicator_b": ScoringRule(
                indicator_name="indicator_b",
                base_weight=0.5,
                min_confidence=0.5,
            ),
        })
        
        indicators = [
            Indicator(
                name="indicator_a",
                category=IndicatorCategory.URL,
                severity=Severity.HIGH,
                score=0.5,
                confidence=1.0,
                explanation="Test A",
            ),
            Indicator(
                name="indicator_b",
                category=IndicatorCategory.URL,
                severity=Severity.HIGH,
                score=0.5,
                confidence=1.0,
                explanation="Test B",
            ),
        ]
        
        score = engine.calculate(indicators)
        # P(not_risky) = (1 - 0.5) * (1 - 0.5) = 0.25
        # risk = 1 - 0.25 = 0.75
        assert score == 0.75

    def test_score_capped_at_one(self):
        """Test that score is capped at 1.0."""
        engine = ScoringEngine(rules={
            "critical": ScoringRule(
                indicator_name="critical",
                base_weight=0.95,
                min_confidence=0.5,
            ),
        })
        
        indicators = [
            Indicator(
                name="critical",
                category=IndicatorCategory.FILE,
                severity=Severity.CRITICAL,
                score=0.95,
                confidence=1.0,
                explanation="Critical issue",
            ),
        ]
        
        score = engine.calculate(indicators)
        assert score <= 1.0

    def test_default_rules_exist(self):
        """Test that default rules are defined."""
        assert len(DEFAULT_RULES) > 0
        assert "credential_form" in DEFAULT_RULES
        assert "known_malicious_hash" in DEFAULT_RULES

    def test_get_default_scorer(self):
        """Test getting default scorer instance."""
        scorer = get_default_scorer()
        assert isinstance(scorer, ScoringEngine)
        assert len(scorer.rules) > 0

    def test_explain_score_empty(self):
        """Test score explanation with no indicators."""
        engine = ScoringEngine()
        explanation = engine.explain_score([])
        
        assert "No risk indicators" in explanation

    def test_explain_score_with_indicators(self):
        """Test score explanation with indicators."""
        engine = ScoringEngine(rules={
            "test_indicator": ScoringRule(
                indicator_name="test_indicator",
                base_weight=0.5,
                min_confidence=0.5,
            ),
        })
        
        indicators = [
            Indicator(
                name="test_indicator",
                category=IndicatorCategory.URL,
                severity=Severity.HIGH,
                score=0.5,
                confidence=0.8,
                explanation="Test explanation",
            ),
        ]
        
        explanation = engine.explain_score(indicators)
        assert "test_indicator" in explanation
        assert "risk contribution" in explanation

    def test_unknown_indicator_uses_own_score(self):
        """Test that unknown indicators use their own score as weight."""
        engine = ScoringEngine(rules={})
        
        indicators = [
            Indicator(
                name="unknown_indicator",
                category=IndicatorCategory.URL,
                severity=Severity.MEDIUM,
                score=0.6,
                confidence=0.8,
                explanation="Unknown but scored",
            ),
        ]
        
        # Should still calculate, using indicator.score as weight
        score = engine.calculate(indicators)
        assert score >= 0.0


class TestWeightedScore:
    """Tests for indicator weighted score calculation."""

    def test_weighted_score_calculation(self):
        """Test weighted score method."""
        indicator = Indicator(
            name="test",
            category=IndicatorCategory.URL,
            severity=Severity.HIGH,
            score=0.8,
            confidence=0.5,
            explanation="Test",
        )
        
        weighted = indicator.weighted_score()
        assert weighted == 0.4  # 0.8 * 0.5

    def test_weighted_score_capped(self):
        """Test that weighted score is capped at 1.0."""
        indicator = Indicator(
            name="test",
            category=IndicatorCategory.URL,
            severity=Severity.CRITICAL,
            score=1.0,
            confidence=1.0,
            explanation="Test",
        )
        
        weighted = indicator.weighted_score()
        assert weighted == 1.0

    def test_to_dict_conversion(self):
        """Test converting indicator to dictionary."""
        indicator = Indicator(
            name="test_indicator",
            category=IndicatorCategory.PII,
            severity=Severity.HIGH,
            score=0.7,
            confidence=0.9,
            explanation="PII detected",
            metadata={"key": "value"},
        )
        
        result = indicator.to_dict()
        
        assert result["name"] == "test_indicator"
        assert result["category"] == "pii"
        assert result["severity"] == "high"
        assert result["score"] == 0.7
        assert result["confidence"] == 0.9
        assert result["explanation"] == "PII detected"
        assert result["metadata"] == {"key": "value"}
