"""Redis Streams consumer for artifact analysis."""

import asyncio
import json
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import redis.asyncio as redis

from shared.events import SuspiciousArtifactSubmitted, ArtifactType
from shared.logging import get_logger
from ingress.deduplication import DeduplicationService
from domain.artifact import NormalizedArtifact

logger = get_logger(__name__)


class ConsumerService:
    """Consumes artifacts from Redis Streams."""

    def __init__(
        self,
        redis_url: str,
        stream_name: str = "artifact.submitted",
        group_name: str = "artifact_guard_group",
        consumer_name: str = "worker_1",
        dedup_service: DeduplicationService | None = None,
    ):
        self.redis_url = redis_url
        self.stream_name = stream_name
        self.group_name = group_name
        self.consumer_name = consumer_name
        self.dedup_service = dedup_service or DeduplicationService()
        self.redis: redis.Redis | None = None
        self._running = False

    async def connect(self) -> None:
        """Connect to Redis and create consumer group."""
        self.redis = redis.from_url(
            self.redis_url,
            encoding="utf-8",
            decode_responses=False,
        )

        try:
            await self.redis.xgroup_create(
                self.stream_name,
                self.group_name,
                id="0",
                mkstream=True,
            )
            logger.info(f"Consumer group '{self.group_name}' created")
        except Exception as e:
            if "BUSYGROUP" not in str(e):
                raise
            logger.info(f"Consumer group '{self.group_name}' already exists")

    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self.redis:
            await self.redis.close()
            self.redis = None

    async def _parse_event(self, data: dict[bytes, bytes]) -> SuspiciousArtifactSubmitted | None:
        """Parse raw Redis event to SuspiciousArtifactSubmitted."""
        try:
            event_data = {}
            for key, value in data.items():
                event_data[key.decode("utf-8")] = value.decode("utf-8")

            # Parse nested JSON fields
            if "correlation_id" in event_data:
                event_data["correlation_id"] = UUID(event_data["correlation_id"])
            if "event_id" in event_data:
                event_data["event_id"] = UUID(event_data["event_id"])
            if "created_at" in event_data:
                event_data["created_at"] = datetime.fromisoformat(
                    event_data["created_at"].replace("Z", "+00:00")
                )

            return SuspiciousArtifactSubmitted(**event_data)
        except Exception as e:
            logger.error(f"Failed to parse event: {e}")
            return None

    async def process_message(
        self, message_id: bytes, data: dict[bytes, bytes]
    ) -> tuple[bool, NormalizedArtifact | None]:
        """Process a single message from the stream.
        
        Returns:
            Tuple of (should_acknowledge, normalized_artifact or None)
        """
        event = await self._parse_event(data)
        if not event:
            logger.warning(f"Invalid event format, message {message_id} will be skipped")
            return True, None

        # Check for duplicates
        is_duplicate = await self.dedup_service.is_duplicate(event)
        if is_duplicate:
            logger.info(f"Duplicate artifact detected: {event.event_id}")
            return True, None

        # Normalize the artifact
        try:
            normalized = await self._normalize_artifact(event)
            logger.info(f"Artifact normalized: {event.event_id}")
            return True, normalized
        except Exception as e:
            logger.error(f"Failed to normalize artifact {event.event_id}: {e}")
            return False, None

    async def _normalize_artifact(
        self, event: SuspiciousArtifactSubmitted
    ) -> NormalizedArtifact:
        """Normalize artifact based on type."""
        if event.artifact_type == ArtifactType.URL:
            from policy.url_policy import normalize_and_validate_url

            normalized_value = await normalize_and_validate_url(event.value)
            return NormalizedArtifact(
                original_value=event.value,
                normalized_value=normalized_value,
                artifact_type=ArtifactType.URL,
            )
        elif event.artifact_type == ArtifactType.DOMAIN:
            normalized_value = event.value.lower().rstrip(".")
            return NormalizedArtifact(
                original_value=event.value,
                normalized_value=normalized_value,
                artifact_type=ArtifactType.DOMAIN,
            )
        else:
            # For files and text, just trim whitespace
            normalized_value = event.value.strip()
            return NormalizedArtifact(
                original_value=event.value,
                normalized_value=normalized_value,
                artifact_type=event.artifact_type,
            )

    async def consume_loop(
        self,
        handler: callable,
        batch_size: int = 10,
        block_timeout: int = 5000,
    ) -> None:
        """Main consumption loop.
        
        Args:
            handler: Async function to handle normalized artifacts
            batch_size: Number of messages to fetch per iteration
            block_timeout: Timeout in ms to block waiting for messages
        """
        if not self.redis:
            raise RuntimeError("Not connected to Redis")

        self._running = True
        logger.info(f"Starting consumption from {self.stream_name}")

        while self._running:
            try:
                messages = await self.redis.xreadgroup(
                    groupname=self.group_name,
                    consumername=self.consumer_name,
                    streams={self.stream_name: ">"},
                    count=batch_size,
                    block=block_timeout,
                )

                if not messages:
                    continue

                for stream_name, stream_messages in messages:
                    for message_id, data in stream_messages:
                        should_ack, artifact = await self.process_message(
                            message_id, data
                        )

                        if artifact:
                            try:
                                await handler(artifact)
                                await self.redis.xack(
                                    self.stream_name, self.group_name, message_id
                                )
                            except Exception as e:
                                logger.error(f"Handler failed for {message_id}: {e}")
                                # Don't acknowledge, will be retried
                        elif should_ack:
                            await self.redis.xack(
                                self.stream_name, self.group_name, message_id
                            )

            except Exception as e:
                logger.error(f"Error in consume loop: {e}")
                await asyncio.sleep(1)

    def stop(self) -> None:
        """Stop the consumption loop."""
        self._running = False
