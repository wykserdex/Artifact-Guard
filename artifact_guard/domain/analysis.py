"""Domain models for analysis."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID, uuid4
from urllib.parse import urlsplit

from shared.events import ArtifactType, Indicator, VerdictType


@dataclass
class AnalysisRequest:
    """Request to analyze an artifact."""

    correlation_id: UUID
    artifact_type: ArtifactType
    value: str
    source_system: str = "untilscam"
    source_chat_hash: str | None = None
    source_message_hash: str | None = None
    context_excerpt: str | None = None
    priority: int = 0  # Higher = more urgent


@dataclass
class AnalysisContext:
    """
    Context maintained throughout the analysis pipeline.

    Contains all state needed during analysis execution.
    """

    analysis_id: UUID = field(default_factory=uuid4)
    correlation_id: UUID = field(default_factory=uuid4)
    artifact_type: ArtifactType = ArtifactType.URL
    artifact_value: str = ""

    risk_score: float = 0.0
    verdict: VerdictType | None = None

    passive_indicators: list[Indicator] = field(default_factory=list)
    active_indicators: list[Indicator] = field(default_factory=list)

    evidence_ids: list[UUID] = field(default_factory=list)

    started_at: datetime | None = None
    completed_at: datetime | None = None

    # Runtime state populated during analysis
    _hostname: str | None = None
    _normalized_hostname: str | None = None
    
    dns_records: list = field(default_factory=list)
    resolved_ips: list[str] = field(default_factory=list)
    rdap_result: object | None = None
    reputation_result: object | None = None

    @property
    def hostname(self) -> str | None:
        """Extract hostname from artifact value if URL."""
        if self._hostname is not None:
            return self._hostname
        
        if self.artifact_type == ArtifactType.URL and self.artifact_value:
            try:
                parsed = urlsplit(self.artifact_value)
                if parsed.hostname:
                    self._hostname = parsed.hostname
                    return self._hostname
            except Exception:
                pass
        elif self.artifact_type == ArtifactType.DOMAIN and self.artifact_value:
            self._hostname = self.artifact_value
            return self._hostname
        
        return None

    @property
    def normalized_hostname(self) -> str | None:
        """Get normalized hostname (after homoglyph normalization)."""
        return self._normalized_hostname or self.hostname

    @normalized_hostname.setter
    def normalized_hostname(self, value: str) -> None:
        """Set normalized hostname."""
        self._normalized_hostname = value


@dataclass
class AnalysisResult:
    """Result of artifact analysis."""

    correlation_id: UUID
    verdict: VerdictType
    risk_score: float
    analysis_id: UUID = field(default_factory=uuid4)
    indicators: list[Indicator] = field(default_factory=list)
    evidence_ids: list[UUID] = field(default_factory=list)
    processing_time_ms: int = 0
    error_message: str | None = None
    completed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AnalysisProgress:
    """Progress update during analysis."""

    analysis_id: UUID
    stage: str
    progress_percent: float
    message: str | None = None
