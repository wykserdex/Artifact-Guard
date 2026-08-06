"""Redis Streams producer for publishing analysis results."""

import json
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import redis.asyncio as redis

from shared.events import (
    ArtifactAnalysisCompleted,
    AnalysisFailed,
    Indicator,
)
from shared.logging import get_logger

logger = get_logger(__name__)


class ProducerService:
    """Publishes analysis results to Redis Streams."""

    def __init__(
        self,
        redis_url: str,
        completed_stream: str = "artifact.completed",
        failed_stream: str = "artifact.failed",
    ):
        self.redis_url = redis_url
        self.completed_stream = completed_stream
        self.failed_stream = failed_stream
        self.redis: redis.Redis | None = None

    async def connect(self) -> None:
        """Connect to Redis."""
        self.redis = redis.from_url(
            self.redis_url,
            encoding="utf-8",
            decode_responses=True,
        )
        logger.info("Connected to Redis for publishing")

    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self.redis:
            await self.redis.close()
            self.redis = None

    def _serialize_uuid(self, obj: Any) -> str:
        """Serialize UUID objects to strings."""
        if isinstance(obj, UUID):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

    async def publish_completed(
        self,
        result: ArtifactAnalysisCompleted,
    ) -> str:
        """Publish successful analysis result.
        
        Returns:
            Message ID in the stream
        """
        if not self.redis:
            raise RuntimeError("Not connected to Redis")

        event_data = {
            "schema_version": str(result.schema_version),
            "event_id": str(result.event_id),
            "correlation_id": str(result.correlation_id),
            "analysis_id": str(result.analysis_id),
            "verdict": result.verdict,
            "risk_score": str(result.risk_score),
            "indicators": json.dumps(
                [
                    {
                        "name": ind.name,
                        "score": str(ind.score),
                        "severity": ind.severity,
                        "explanation": ind.explanation,
                        "evidence_ids": [str(eid) for eid in ind.evidence_ids],
                    }
                    for ind in result.indicators
                ]
            ),
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }

        message_id = await self.redis.xadd(
            self.completed_stream,
            event_data,
        )
        logger.info(
            f"Published completed analysis {result.analysis_id} "
            f"with verdict {result.verdict}"
        )
        return message_id

    async def publish_failed(
        self,
        error: AnalysisFailed,
    ) -> str:
        """Publish failed analysis result.
        
        Returns:
            Message ID in the stream
        """
        if not self.redis:
            raise RuntimeError("Not connected to Redis")

        event_data = {
            "schema_version": str(error.schema_version),
            "event_id": str(error.event_id),
            "correlation_id": str(error.correlation_id),
            "analysis_id": str(error.analysis_id) if error.analysis_id else "",
            "error_type": error.error_type,
            "error_message": error.error_message,
            "retryable": str(error.retryable).lower(),
            "failed_at": datetime.now(timezone.utc).isoformat(),
        }

        message_id = await self.redis.xadd(
            self.failed_stream,
            event_data,
        )
        logger.warning(f"Published failed analysis: {error.error_message}")
        return message_id

    async def move_to_dead_letter(
        self,
        source_stream: str,
        message_id: bytes,
        reason: str,
    ) -> str:
        """Move a failed message to dead letter stream.
        
        Args:
            source_stream: Original stream name
            message_id: ID of the failed message
            reason: Reason for moving to dead letter
            
        Returns:
            Message ID in dead letter stream
        """
        if not self.redis:
            raise RuntimeError("Not connected to Redis")

        dead_letter_stream = "artifact.dead_letter"

        # Read original message
        messages = await self.redis.xrange(source_stream, min=message_id, max=message_id)
        if not messages:
            logger.error(f"Could not find message {message_id} in {source_stream}")
            return ""

        _, data = messages[0]
        data["dead_letter_reason"] = reason
        data["dead_letter_source"] = source_stream
        data["dead_letter_at"] = datetime.now(timezone.utc).isoformat()

        new_message_id = await self.redis.xadd(dead_letter_stream, data)
        
        # Acknowledge and delete from source
        await self.redis.xack(source_stream, "artifact_guard_group", message_id)
        await self.redis.xdel(source_stream, message_id)

        logger.warning(f"Moved message {message_id} to dead letter: {reason}")
        return new_message_id
