"""Evidence models for storing analysis proofs."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from uuid import UUID, uuid4


class EvidenceType(StrEnum):
    """Types of evidence that can be collected."""
    SCREENSHOT = "screenshot"
    HTML_SNAPSHOT = "html_snapshot"
    FILE_COPY = "file_copy"
    DNS_RECORD = "dns_record"
    TLS_CERTIFICATE = "tls_certificate"
    RDAP_DATA = "rdap_data"
    REDIRECT_CHAIN = "redirect_chain"
    FORM_DATA = "form_data"
    OCR_RESULT = "ocr_result"
    YARA_MATCH = "yara_match"
    ANTIVIRUS_REPORT = "antivirus_report"


@dataclass
class EvidenceManifest:
    """Manifest for an evidence object."""
    
    analysis_id: UUID
    evidence_type: EvidenceType
    content_type: str
    size: int
    sha256: str
    source: str
    
    evidence_id: UUID = field(default_factory=uuid4)
    collected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    retention_until: datetime | None = None
    
    contains_pii: bool = False
    encrypted: bool = True
    redacted: bool = False
    
    policy_version: str = "v1"
    metadata: dict = field(default_factory=dict)
    
    def compute_retention(self, retention_days: int) -> None:
        """Compute retention deadline based on policy."""
        from datetime import timedelta
        self.retention_until = self.collected_at + timedelta(days=retention_days)


@dataclass
class EvidenceReference:
    """Lightweight reference to evidence (for indicators)."""
    
    evidence_id: UUID
    evidence_type: EvidenceType
    description: str
    thumbnail_url: str | None = None
