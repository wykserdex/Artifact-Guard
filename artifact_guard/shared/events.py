from datetime import datetime, timezone
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class ArtifactType(StrEnum):
    """Supported artifact types for analysis."""
    URL = "url"
    DOMAIN = "domain"
    FILE = "file"
    TEXT = "text"


class SuspiciousArtifactSubmitted(BaseModel):
    """Event sent when a suspicious artifact is submitted for analysis."""
    
    schema_version: int = 1
    event_id: UUID = Field(default_factory=uuid4)
    correlation_id: UUID
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    artifact_type: ArtifactType
    value: str

    source_system: str = "untilscam"
    source_chat_hash: str | None = None
    source_message_hash: str | None = None
    
    # Do not transmit full messages without necessity.
    context_excerpt: str | None = Field(default=None, max_length=1000)


class Indicator(BaseModel):
    """Single indicator detected during analysis."""
    
    name: str
    score: float = Field(ge=0, le=1)
    severity: str
    explanation: str
    evidence_ids: list[UUID] = Field(default_factory=list)


class VerdictType(StrEnum):
    """Possible verdict outcomes."""
    ALLOW = "ALLOW"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    PROCESSING_ERROR = "PROCESSING_ERROR"


class ArtifactAnalysisCompleted(BaseModel):
    """Event sent when artifact analysis is completed."""
    
    schema_version: int = 1
    event_id: UUID = Field(default_factory=uuid4)
    correlation_id: UUID
    analysis_id: UUID
    verdict: VerdictType
    risk_score: float = Field(ge=0, le=1)
    indicators: list[Indicator] = Field(default_factory=list)
    processing_time_ms: int | None = None
    error_message: str | None = None


class AnalysisFailed(BaseModel):
    """Event sent when analysis fails."""
    
    schema_version: int = 1
    event_id: UUID = Field(default_factory=uuid4)
    correlation_id: UUID
    analysis_id: UUID | None = None
    error_type: str
    error_message: str
    retryable: bool = True
