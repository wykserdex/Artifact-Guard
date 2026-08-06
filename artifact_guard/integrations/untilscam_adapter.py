"""Integration adapter for untilscam_v3 to publish artifacts to Artifact Guard."""

from uuid import UUID, uuid4
from datetime import datetime, timezone
from typing import Any

from shared.events import SuspiciousArtifactSubmitted, ArtifactType
from shared.logging import get_logger

logger = get_logger(__name__)


class SecureHashProvider:
    """Provides secure hashing for chat/message IDs."""

    def __init__(self, salt: str = "default_salt_change_in_production"):
        self.salt = salt

    def hash_id(self, value: str) -> str:
        """Hash an ID with salt."""
        import hashlib
        return hashlib.sha256(
            f"{value}:{self.salt}".encode("utf-8")
        ).hexdigest()


class ArtifactGuardPublisher:
    """Publishes artifacts from untilscam_v3 to Artifact Guard."""

    def __init__(
        self,
        producer: Any,  # Broker producer interface
        stream_name: str = "artifact.submitted",
        hash_provider: SecureHashProvider | None = None,
    ):
        self.producer = producer
        self.stream_name = stream_name
        self.hash_provider = hash_provider or SecureHashProvider()

    async def submit_url(
        self,
        *,
        correlation_id: str | UUID,
        url: str,
        chat_id: int,
        message_id: int,
        context_excerpt: str | None = None,
    ) -> UUID:
        """Submit a URL artifact for analysis.
        
        Args:
            correlation_id: Correlation ID from untilscam_v3
            url: The URL to analyze
            chat_id: Telegram chat ID (will be hashed)
            message_id: Telegram message ID (will be hashed)
            context_excerpt: Optional context from the message
            
        Returns:
            Event ID for tracking
        """
        if isinstance(correlation_id, str):
            correlation_id = UUID(correlation_id)

        event = SuspiciousArtifactSubmitted(
            correlation_id=correlation_id,
            artifact_type=ArtifactType.URL,
            value=url,
            source_system="untilscam",
            source_chat_hash=self.hash_provider.hash_id(str(chat_id)),
            source_message_hash=self.hash_provider.hash_id(f"{chat_id}:{message_id}"),
            context_excerpt=context_excerpt[:1000] if context_excerpt else None,
        )

        await self._publish_event(event)
        logger.info(f"Submitted URL {url[:50]}... for analysis (event: {event.event_id})")
        return event.event_id

    async def submit_domain(
        self,
        *,
        correlation_id: str | UUID,
        domain: str,
        chat_id: int,
        message_id: int,
        context_excerpt: str | None = None,
    ) -> UUID:
        """Submit a domain artifact for analysis.
        
        Args:
            correlation_id: Correlation ID from untilscam_v3
            domain: The domain to analyze
            chat_id: Telegram chat ID (will be hashed)
            message_id: Telegram message ID (will be hashed)
            context_excerpt: Optional context from the message
            
        Returns:
            Event ID for tracking
        """
        if isinstance(correlation_id, str):
            correlation_id = UUID(correlation_id)

        event = SuspiciousArtifactSubmitted(
            correlation_id=correlation_id,
            artifact_type=ArtifactType.DOMAIN,
            value=domain,
            source_system="untilscam",
            source_chat_hash=self.hash_provider.hash_id(str(chat_id)),
            source_message_hash=self.hash_provider.hash_id(f"{chat_id}:{message_id}"),
            context_excerpt=context_excerpt[:1000] if context_excerpt else None,
        )

        await self._publish_event(event)
        logger.info(f"Submitted domain {domain} for analysis (event: {event.event_id})")
        return event.event_id

    async def submit_file_hash(
        self,
        *,
        correlation_id: str | UUID,
        file_hash: str,  # SHA-256 of the file
        file_name: str,
        file_size: int,
        chat_id: int,
        message_id: int,
        context_excerpt: str | None = None,
    ) -> UUID:
        """Submit a file hash for analysis.
        
        Note: Only the hash is submitted, not the actual file content.
        The file should be stored in object storage separately.
        
        Args:
            correlation_id: Correlation ID from untilscam_v3
            file_hash: SHA-256 hash of the file
            file_name: Original file name
            file_size: File size in bytes
            chat_id: Telegram chat ID (will be hashed)
            message_id: Telegram message ID (will be hashed)
            context_excerpt: Optional context from the message
            
        Returns:
            Event ID for tracking
        """
        if isinstance(correlation_id, str):
            correlation_id = UUID(correlation_id)

        # Include metadata in the value for deduplication
        value = f"{file_hash}:{file_name}:{file_size}"

        event = SuspiciousArtifactSubmitted(
            correlation_id=correlation_id,
            artifact_type=ArtifactType.FILE,
            value=value,
            source_system="untilscam",
            source_chat_hash=self.hash_provider.hash_id(str(chat_id)),
            source_message_hash=self.hash_provider.hash_id(f"{chat_id}:{message_id}"),
            context_excerpt=context_excerpt[:1000] if context_excerpt else None,
        )

        await self._publish_event(event)
        logger.info(f"Submitted file hash {file_hash[:16]}... for analysis (event: {event.event_id})")
        return event.event_id

    async def submit_text(
        self,
        *,
        correlation_id: str | UUID,
        text: str,
        chat_id: int,
        message_id: int,
        context_excerpt: str | None = None,
    ) -> UUID:
        """Submit text content for PII/scam analysis.
        
        Args:
            correlation_id: Correlation ID from untilscam_v3
            text: The text to analyze
            chat_id: Telegram chat ID (will be hashed)
            message_id: Telegram message ID (will be hashed)
            context_excerpt: Optional additional context
            
        Returns:
            Event ID for tracking
        """
        if isinstance(correlation_id, str):
            correlation_id = UUID(correlation_id)

        event = SuspiciousArtifactSubmitted(
            correlation_id=correlation_id,
            artifact_type=ArtifactType.TEXT,
            value=text,
            source_system="untilscam",
            source_chat_hash=self.hash_provider.hash_id(str(chat_id)),
            source_message_hash=self.hash_provider.hash_id(f"{chat_id}:{message_id}"),
            context_excerpt=context_excerpt[:1000] if context_excerpt else None,
        )

        await self._publish_event(event)
        logger.info(f"Submitted text ({len(text)} chars) for analysis (event: {event.event_id})")
        return event.event_id

    async def _publish_event(self, event: SuspiciousArtifactSubmitted) -> None:
        """Publish event to the broker."""
        event_data = {
            "schema_version": str(event.schema_version),
            "event_id": str(event.event_id),
            "correlation_id": str(event.correlation_id),
            "created_at": event.created_at.isoformat(),
            "artifact_type": event.artifact_type.value,
            "value": event.value,
            "source_system": event.source_system,
            "source_chat_hash": event.source_chat_hash or "",
            "source_message_hash": event.source_message_hash or "",
            "context_excerpt": event.context_excerpt or "",
        }

        await self.producer.publish(
            stream=self.stream_name,
            event=event_data,
        )
