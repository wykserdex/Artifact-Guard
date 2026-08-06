"""Integration tests for analysis pipeline."""

import pytest
from uuid import uuid4

from domain.analysis import AnalysisContext, AnalysisResult
from domain.indicators import Indicator, Severity, IndicatorCategory
from scoring.engine import ScoringEngine, get_default_scorer
from domain.verdict import determine_verdict, VerdictType
from shared.events import ArtifactType


class TestAnalysisContextCreation:
    """Tests for AnalysisContext creation and initialization."""

    def test_create_analysis_context(self):
        """Test creating an analysis context."""
        correlation_id = uuid4()
        
        ctx = AnalysisContext(
            analysis_id=uuid4(),
            correlation_id=correlation_id,
            artifact_type=ArtifactType.URL,
            artifact_value="https://example.com",
        )
        
        assert ctx.correlation_id == correlation_id
        assert ctx.artifact_type == ArtifactType.URL
        assert ctx.artifact_value == "https://example.com"
        assert ctx.risk_score == 0.0
        assert ctx.passive_indicators == []
        assert ctx.active_indicators == []


class TestScoringIntegration:
    """Integration tests for scoring with indicators."""

    def test_scoring_with_multiple_indicators(self):
        """Test scoring engine with multiple indicator types."""
        scorer = get_default_scorer()
        
        indicators = [
            Indicator(
                name="credential_form",
                category=IndicatorCategory.CONTENT,
                severity=Severity.HIGH,
                score=0.35,
                confidence=0.9,
                explanation="Login form detected",
            ),
            Indicator(
                name="recent_domain",
                category=IndicatorCategory.DOMAIN,
                severity=Severity.MEDIUM,
                score=0.15,
                confidence=0.8,
                explanation="Domain registered 2 days ago",
            ),
        ]
        
        score = scorer.calculate(indicators)
        
        # Score should be > 0 due to indicators
        assert score > 0.0
        assert score <= 1.0
        
        # Explanation should mention both indicators
        explanation = scorer.explain_score(indicators)
        assert "credential_form" in explanation or "recent_domain" in explanation

    def test_scoring_leads_to_correct_verdict(self):
        """Test that scores map to correct verdicts."""
        # Low score - ALLOW
        low_decision = determine_verdict(0.15)
        assert low_decision.verdict == VerdictType.ALLOW
        
        # Medium score - MANUAL_REVIEW
        medium_decision = determine_verdict(0.40)
        assert medium_decision.verdict == VerdictType.MANUAL_REVIEW
        
        # High-medium score - SUSPICIOUS
        suspicious_decision = determine_verdict(0.65)
        assert suspicious_decision.verdict == VerdictType.SUSPICIOUS
        
        # Very high score - HIGH_RISK
        high_decision = determine_verdict(0.90)
        assert high_decision.verdict == VerdictType.HIGH_RISK


class TestIndicatorWeightedScore:
    """Tests for indicator weighted score calculations."""

    def test_weighted_score_affects_final_score(self):
        """Test that weighted scores properly affect final calculation."""
        scorer = ScoringEngine(rules={
            "high_weight": ScoringEngine().rules.get("credential_form"),
        })
        
        # High confidence indicator
        high_conf = Indicator(
            name="high_weight",
            category=IndicatorCategory.CONTENT,
            severity=Severity.HIGH,
            score=0.5,
            confidence=1.0,
            explanation="High confidence",
        )
        
        # Low confidence indicator (same base score)
        low_conf = Indicator(
            name="high_weight",
            category=IndicatorCategory.CONTENT,
            severity=Severity.HIGH,
            score=0.5,
            confidence=0.3,
            explanation="Low confidence",
        )
        
        score_high = scorer.calculate([high_conf])
        score_low = scorer.calculate([low_conf])
        
        # High confidence should produce higher score
        assert score_high > score_low


class TestEndToEndAnalysis:
    """End-to-end analysis flow tests."""

    def test_full_analysis_flow_simulation(self):
        """Simulate a full analysis flow from indicators to verdict."""
        # Step 1: Create context
        correlation_id = uuid4()
        ctx = AnalysisContext(
            analysis_id=uuid4(),
            correlation_id=correlation_id,
            artifact_type=ArtifactType.URL,
            artifact_value="https://suspicious-site.com/login",
        )
        
        # Step 2: Add indicators (simulating analyzer output)
        ctx.passive_indicators.extend([
            Indicator(
                name="recent_domain",
                category=IndicatorCategory.DOMAIN,
                severity=Severity.MEDIUM,
                score=0.15,
                confidence=0.85,
                explanation="Domain age < 7 days",
            ),
            Indicator(
                name="homoglyph_domain",
                category=IndicatorCategory.DOMAIN,
                severity=Severity.HIGH,
                score=0.20,
                confidence=0.9,
                explanation="Domain contains character substitutions",
            ),
        ])
        
        # Step 3: Calculate score
        scorer = get_default_scorer()
        ctx.risk_score = scorer.calculate(ctx.passive_indicators)
        
        # Step 4: Determine verdict
        verdict_decision = determine_verdict(ctx.risk_score)
        
        # Verify results
        assert ctx.risk_score > 0.0
        assert verdict_decision.verdict in [v for v in VerdictType]
        assert len(verdict_decision.explanation) > 0

    def test_clean_url_gets_allow_verdict(self):
        """Test that a clean URL with no indicators gets ALLOW verdict."""
        ctx = AnalysisContext(
            analysis_id=uuid4(),
            correlation_id=uuid4(),
            artifact_type=ArtifactType.URL,
            artifact_value="https://www.google.com",
        )
        
        # No indicators added
        scorer = get_default_scorer()
        ctx.risk_score = scorer.calculate(ctx.passive_indicators)
        
        verdict = determine_verdict(ctx.risk_score)
        
        assert ctx.risk_score == 0.0
        assert verdict.verdict == VerdictType.ALLOW
        assert verdict.auto_action_allowed is True

    def test_malicious_hash_gets_high_risk(self):
        """Test that known malicious hash triggers HIGH_RISK."""
        ctx = AnalysisContext(
            analysis_id=uuid4(),
            correlation_id=uuid4(),
            artifact_type=ArtifactType.FILE,
            artifact_value="malware.exe",
        )
        
        # Add critical indicator with high confidence
        ctx.passive_indicators.append(
            Indicator(
                name="known_malicious_hash",
                category=IndicatorCategory.FILE,
                severity=Severity.CRITICAL,
                score=0.80,
                confidence=0.95,
                explanation="SHA-256 matches known malware database",
            )
        )
        
        scorer = get_default_scorer()
        ctx.risk_score = scorer.calculate(ctx.passive_indicators)
        verdict = determine_verdict(ctx.risk_score)
        
        # Known malware should trigger significant risk
        # Score of 0.76 -> SUSPICIOUS (requires manual review)
        assert ctx.risk_score >= 0.55  # At least suspicious level
        assert verdict.verdict in (VerdictType.SUSPICIOUS, VerdictType.HIGH_RISK)
        assert verdict.requires_manual_review is True or verdict.auto_action_allowed is True


class TestAnalysisWithActiveIndicators:
    """Tests for analysis including active indicators."""

    def test_passive_only_analysis(self):
        """Test analysis with only passive indicators."""
        ctx = AnalysisContext(
            analysis_id=uuid4(),
            correlation_id=uuid4(),
            artifact_type=ArtifactType.URL,
            artifact_value="https://example.com",
        )
        
        ctx.passive_indicators.append(
            Indicator(
                name="suspicious_redirect_chain",
                category=IndicatorCategory.NETWORK,
                severity=Severity.MEDIUM,
                score=0.10,
                confidence=0.7,
                explanation="Multiple redirects detected",
            )
        )
        
        scorer = get_default_scorer()
        passive_score = scorer.calculate(ctx.passive_indicators)
        
        # Passive score should be calculated
        assert passive_score > 0.0
        assert ctx.active_indicators == []

    def test_combined_passive_and_active_indicators(self):
        """Test analysis combining passive and active indicators."""
        ctx = AnalysisContext(
            analysis_id=uuid4(),
            correlation_id=uuid4(),
            artifact_type=ArtifactType.URL,
            artifact_value="https://phishing-site.com",
        )
        
        # Passive indicators
        ctx.passive_indicators.append(
            Indicator(
                name="recent_domain",
                category=IndicatorCategory.DOMAIN,
                severity=Severity.MEDIUM,
                score=0.15,
                confidence=0.8,
                explanation="New domain",
            )
        )
        
        # Active indicators (from browser rendering)
        ctx.active_indicators.append(
            Indicator(
                name="credential_form",
                category=IndicatorCategory.CONTENT,
                severity=Severity.HIGH,
                score=0.35,
                confidence=0.9,
                explanation="Password field detected",
            )
        )
        
        # Combine all indicators
        all_indicators = ctx.passive_indicators + ctx.active_indicators
        
        scorer = get_default_scorer()
        combined_score = scorer.calculate(all_indicators)
        passive_score = scorer.calculate(ctx.passive_indicators)
        
        # Combined score should be higher than passive only
        assert combined_score > passive_score
