"""Shared module for Artifact Guard."""

from .config import config
from .logging import get_logger, setup_logging
from .hashing import compute_sha256, compute_idempotency_key, secure_hash
from .redaction import redact_text, contains_pii
from .events import (
    ArtifactType,
    SuspiciousArtifactSubmitted,
    Indicator,
    VerdictType,
    ArtifactAnalysisCompleted,
    AnalysisFailed,
)

__all__ = [
    "config",
    "get_logger",
    "setup_logging",
    "compute_sha256",
    "compute_idempotency_key",
    "secure_hash",
    "redact_text",
    "contains_pii",
    "ArtifactType",
    "SuspiciousArtifactSubmitted",
    "Indicator",
    "VerdictType",
    "ArtifactAnalysisCompleted",
    "AnalysisFailed",
]
