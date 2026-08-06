"""Domain models for Artifact Guard."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from uuid import UUID, uuid4

from shared.events import ArtifactType, VerdictType


@dataclass
class RawArtifact:
    """Raw artifact extracted from a message before normalization."""
    
    artifact_type: ArtifactType
    value: str
    context: str | None = None


@dataclass
class NormalizedArtifact:
    """Normalized artifact ready for analysis."""
    
    original_value: str
    normalized_value: str
    artifact_type: ArtifactType
    content_hash: str | None = None
    metadata: dict = field(default_factory=dict)


@dataclass
class Artifact:
    """Represents an artifact to be analyzed."""
    
    artifact_type: ArtifactType
    value: str
    normalized_value: str | None = None
    content_hash: str | None = None
    metadata: dict = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AnalysisContext:
    """Context passed through the analysis pipeline."""
    
    correlation_id: UUID
    artifact: Artifact
    analysis_id: UUID = field(default_factory=uuid4)
    source_system: str = "untilscam"
    source_chat_hash: str | None = None
    source_message_hash: str | None = None
    context_excerpt: str | None = None
    
    # Analysis state
    passive_indicators: list = field(default_factory=list)
    active_indicators: list = field(default_factory=list)
    evidence_ids: list[UUID] = field(default_factory=list)
    
    # Computed results
    risk_score: float = 0.0
    verdict: VerdictType | None = None
    error_message: str | None = None
    
    # Timing
    started_at: datetime | None = None
    completed_at: datetime | None = None


@dataclass
class AnalysisResult:
    """Result of artifact analysis."""
    
    analysis_id: UUID
    correlation_id: UUID
    verdict: VerdictType
    risk_score: float
    indicators: list
    evidence_ids: list[UUID]
    processing_time_ms: int
    error_message: str | None = None
