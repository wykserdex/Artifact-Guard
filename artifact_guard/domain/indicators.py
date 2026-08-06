"""Indicator models for analysis findings."""

from dataclasses import dataclass, field
from enum import StrEnum
from uuid import UUID


class Severity(StrEnum):
    """Severity levels for indicators."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IndicatorCategory(StrEnum):
    """Categories of security indicators."""
    DOMAIN = "domain"
    URL = "url"
    CONTENT = "content"
    FILE = "file"
    NETWORK = "network"
    PII = "pii"
    REPUTATION = "reputation"


@dataclass
class Indicator:
    """
    Represents a single indicator detected during analysis.
    
    Each indicator contributes to the overall risk score.
    """
    
    name: str
    category: IndicatorCategory
    severity: Severity
    score: float  # 0.0 to 1.0
    confidence: float  # 0.0 to 1.0
    explanation: str
    evidence_ids: list[UUID] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    
    def weighted_score(self) -> float:
        """Calculate weighted score considering confidence."""
        return min(1.0, self.score * self.confidence)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "category": self.category.value,
            "severity": self.severity.value,
            "score": self.score,
            "confidence": self.confidence,
            "explanation": self.explanation,
            "evidence_ids": [str(eid) for eid in self.evidence_ids],
            "metadata": self.metadata,
        }


# Predefined indicator templates
INDICATOR_TEMPLATES = {
    "credential_form": Indicator(
        name="credential_form",
        category=IndicatorCategory.CONTENT,
        severity=Severity.HIGH,
        score=0.35,
        confidence=0.9,
        explanation="Page contains a form requesting credentials",
    ),
    "brand_domain_mismatch": Indicator(
        name="brand_domain_mismatch",
        category=IndicatorCategory.DOMAIN,
        severity=Severity.HIGH,
        score=0.25,
        confidence=0.85,
        explanation="Domain does not match the claimed brand",
    ),
    "recent_domain": Indicator(
        name="recent_domain",
        category=IndicatorCategory.DOMAIN,
        severity=Severity.MEDIUM,
        score=0.15,
        confidence=0.8,
        explanation="Domain was registered recently",
    ),
    "homoglyph_domain": Indicator(
        name="homoglyph_domain",
        category=IndicatorCategory.DOMAIN,
        severity=Severity.HIGH,
        score=0.20,
        confidence=0.9,
        explanation="Domain contains homoglyph characters",
    ),
    "suspicious_redirect_chain": Indicator(
        name="suspicious_redirect_chain",
        category=IndicatorCategory.NETWORK,
        severity=Severity.MEDIUM,
        score=0.10,
        confidence=0.75,
        explanation="URL redirects through multiple suspicious domains",
    ),
    "known_malicious_hash": Indicator(
        name="known_malicious_hash",
        category=IndicatorCategory.FILE,
        severity=Severity.CRITICAL,
        score=0.80,
        confidence=0.95,
        explanation="File hash matches known malware",
    ),
    "private_data_exposure": Indicator(
        name="private_data_exposure",
        category=IndicatorCategory.PII,
        severity=Severity.HIGH,
        score=0.45,
        confidence=0.85,
        explanation="Personal identifiable information detected",
    ),
}
