"""Verdict determination logic."""

from dataclasses import dataclass
from enum import StrEnum

from shared.events import VerdictType


@dataclass
class VerdictDecision:
    """Final verdict with explanation."""
    
    verdict: VerdictType
    risk_score: float
    explanation: str
    requires_manual_review: bool = False
    auto_action_allowed: bool = True


def determine_verdict(risk_score: float) -> VerdictDecision:
    """
    Determine verdict based on risk score.
    
    Thresholds:
    - HIGH_RISK: >= 0.85
    - SUSPICIOUS: >= 0.55
    - MANUAL_REVIEW: >= 0.30
    - ALLOW: < 0.30
    """
    
    if risk_score >= 0.85:
        return VerdictDecision(
            verdict=VerdictType.HIGH_RISK,
            risk_score=risk_score,
            explanation="High risk indicators detected. Immediate action recommended.",
            requires_manual_review=False,
            auto_action_allowed=True,
        )
    
    if risk_score >= 0.55:
        return VerdictDecision(
            verdict=VerdictType.SUSPICIOUS,
            risk_score=risk_score,
            explanation="Suspicious patterns detected. Warning or manual review advised.",
            requires_manual_review=True,
            auto_action_allowed=False,
        )
    
    if risk_score >= 0.30:
        return VerdictDecision(
            verdict=VerdictType.MANUAL_REVIEW,
            risk_score=risk_score,
            explanation="Low-confidence signals detected. Manual classification recommended.",
            requires_manual_review=True,
            auto_action_allowed=False,
        )
    
    return VerdictDecision(
        verdict=VerdictType.ALLOW,
        risk_score=risk_score,
        explanation="No significant risk indicators detected.",
        requires_manual_review=False,
        auto_action_allowed=True,
    )


def should_block(verdict: VerdictDecision) -> bool:
    """Determine if automatic blocking is appropriate."""
    return (
        verdict.verdict == VerdictType.HIGH_RISK
        and verdict.auto_action_allowed
    )


def should_alert(verdict: VerdictDecision) -> bool:
    """Determine if an alert should be raised."""
    return verdict.verdict in (VerdictType.HIGH_RISK, VerdictType.SUSPICIOUS)
