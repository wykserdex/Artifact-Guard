"""Domain module for Artifact Guard."""

from .artifact import Artifact, AnalysisContext, AnalysisResult as ArtifactAnalysisResult
from .analysis import AnalysisRequest, AnalysisResult, AnalysisProgress
from .evidence import EvidenceManifest, EvidenceReference, EvidenceType
from .indicators import Indicator, Severity, IndicatorCategory, INDICATOR_TEMPLATES
from .verdict import VerdictDecision, determine_verdict, should_block, should_alert

__all__ = [
    # Artifact
    "Artifact",
    "AnalysisContext",
    "ArtifactAnalysisResult",
    # Analysis
    "AnalysisRequest",
    "AnalysisResult",
    "AnalysisProgress",
    # Evidence
    "EvidenceManifest",
    "EvidenceReference",
    "EvidenceType",
    # Indicators
    "Indicator",
    "Severity",
    "IndicatorCategory",
    "INDICATOR_TEMPLATES",
    # Verdict
    "VerdictDecision",
    "determine_verdict",
    "should_block",
    "should_alert",
]
