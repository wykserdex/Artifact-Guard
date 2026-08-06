"""Scoring engine for calculating risk scores."""

from dataclasses import dataclass, field

from domain.indicators import Indicator


@dataclass
class ScoringRule:
    """Rule for scoring an indicator type."""
    
    indicator_name: str
    base_weight: float  # 0.0 to 1.0
    min_confidence: float = 0.5  # Minimum confidence to consider


# Default scoring rules
DEFAULT_RULES: dict[str, ScoringRule] = {
    "credential_form": ScoringRule(
        indicator_name="credential_form",
        base_weight=0.35,
        min_confidence=0.7,
    ),
    "brand_domain_mismatch": ScoringRule(
        indicator_name="brand_domain_mismatch",
        base_weight=0.25,
        min_confidence=0.7,
    ),
    "recent_domain": ScoringRule(
        indicator_name="recent_domain",
        base_weight=0.15,
        min_confidence=0.6,
    ),
    "homoglyph_domain": ScoringRule(
        indicator_name="homoglyph_domain",
        base_weight=0.20,
        min_confidence=0.8,
    ),
    "suspicious_redirect_chain": ScoringRule(
        indicator_name="suspicious_redirect_chain",
        base_weight=0.10,
        min_confidence=0.6,
    ),
    "known_malicious_hash": ScoringRule(
        indicator_name="known_malicious_hash",
        base_weight=0.80,
        min_confidence=0.9,
    ),
    "private_data_exposure": ScoringRule(
        indicator_name="private_data_exposure",
        base_weight=0.45,
        min_confidence=0.7,
    ),
    "suspicious_ip_range": ScoringRule(
        indicator_name="suspicious_ip_range",
        base_weight=0.20,
        min_confidence=0.5,
    ),
}


@dataclass
class ScoringEngine:
    """
    Deterministic scoring engine for risk calculation.
    
    Uses a probabilistic approach: calculates the probability that
    the artifact is NOT risky, then inverts it.
    """
    
    rules: dict[str, ScoringRule] = field(default_factory=lambda: DEFAULT_RULES.copy())
    
    def calculate(self, indicators: list[Indicator]) -> float:
        """
        Calculate overall risk score from indicators.
        
        Algorithm:
        1. For each indicator above confidence threshold:
           - Calculate contribution = weight * confidence
        2. Combine using probability theory:
           - P(not_risky) = Π(1 - contribution_i)
           - risk_score = 1 - P(not_risky)
        
        Returns:
            Risk score from 0.0 (safe) to 1.0 (highly risky)
        """
        if not indicators:
            return 0.0
        
        probability_not_risky = 1.0
        
        for indicator in indicators:
            rule = self.rules.get(indicator.name)
            if not rule:
                # Use indicator's own score if no rule defined
                weight = indicator.score
            else:
                weight = rule.base_weight
            
            # Skip low-confidence indicators
            if indicator.confidence < rule.min_confidence if rule else 0.5:
                continue
            
            # Calculate contribution
            contribution = min(1.0, weight * indicator.confidence)
            
            # Combine probabilities
            probability_not_risky *= (1.0 - contribution)
        
        risk_score = 1.0 - probability_not_risky
        
        return round(min(1.0, risk_score), 4)
    
    def explain_score(self, indicators: list[Indicator]) -> str:
        """Generate human-readable explanation of the score."""
        if not indicators:
            return "No risk indicators detected."
        
        sorted_indicators = sorted(
            indicators,
            key=lambda i: i.weighted_score(),
            reverse=True,
        )[:5]  # Top 5 contributors
        
        explanations = []
        for ind in sorted_indicators:
            rule = self.rules.get(ind.name)
            weight = rule.base_weight if rule else ind.score
            contribution = weight * ind.confidence
            explanations.append(
                f"{ind.name}: {contribution:.2%} risk contribution"
            )
        
        return "; ".join(explanations)


def get_default_scorer() -> ScoringEngine:
    """Get a scorer with default rules."""
    return ScoringEngine()
