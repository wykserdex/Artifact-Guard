"""Deduplication service for artifact analysis."""

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any

import redis.asyncio as redis

from shared.events import SuspiciousArtifactSubmitted, ArtifactType
from shared.hashing import compute_idempotency_key
from shared.logging import get_logger

logger = get_logger(__name__)


class DeduplicationService:
    """Prevents duplicate artifact processing using idempotency keys."""

    def __init__(
        self,
        redis_url: str | None = None,
        ttl_hours: int = 24,
        policy_version: str = "v1",
    ):
        self.redis_url = redis_url
        self.ttl = timedelta(hours=ttl_hours)
        self.policy_version = policy_version
        self.redis: redis.Redis | None = None
        self._local_cache: dict[str, datetime] = {}

    async def connect(self) -> None:
        """Connect to Redis if URL provided."""
        if self.redis_url:
            self.redis = redis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True,
            )
            logger.info("Connected to Redis for deduplication")

    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self.redis:
            await self.redis.close()
            self.redis = None

    def _compute_idempotency_key(self, event: SuspiciousArtifactSubmitted) -> str:
        """Compute idempotency key for an event.
        
        Key format: SHA-256(artifact_type + normalized_value + policy_version)
        """
        # Normalize value based on type
        value = event.value.strip()
        
        if event.artifact_type == ArtifactType.URL:
            # Normalize URL: lowercase scheme and host, remove fragment
            from urllib.parse import urlsplit, urlunsplit
            
            parsed = urlsplit(value)
            normalized = urlunsplit((
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                parsed.path,
                parsed.query,
                "",  # Remove fragment
            ))
            value = normalized
        elif event.artifact_type == ArtifactType.DOMAIN:
            value = value.lower().rstrip(".")

        return compute_idempotency_key(
            artifact_type=event.artifact_type.value,
            normalized_value=value,
            policy_version=self.policy_version,
        )

    async def is_duplicate(self, event: SuspiciousArtifactSubmitted) -> bool:
        """Check if an event is a duplicate.
        
        Args:
            event: The event to check
            
        Returns:
            True if duplicate, False if new
        """
        key = f"dedup:{self._compute_idempotency_key(event)}"
        now = datetime.now(timezone.utc)

        # Check local cache first (fast path)
        if key in self._local_cache:
            cached_time = self._local_cache[key]
            if now - cached_time < self.ttl:
                logger.debug(f"Duplicate detected in local cache: {key}")
                return True
            else:
                del self._local_cache[key]

        # Check Redis (shared across instances)
        if self.redis:
            try:
                exists = await self.redis.exists(key)
                if exists:
                    logger.debug(f"Duplicate detected in Redis: {key}")
                    return True
            except Exception as e:
                logger.warning(f"Redis check failed, using local cache: {e}")

        # Mark as seen
        await self._mark_as_seen(key)
        return False

    async def _mark_as_seen(self, key: str) -> None:
        """Mark a key as seen in both local cache and Redis."""
        now = datetime.now(timezone.utc)
        
        # Update local cache
        self._local_cache[key] = now
        
        # Update Redis with TTL
        if self.redis:
            try:
                ttl_seconds = int(self.ttl.total_seconds())
                await self.redis.setex(key, ttl_seconds, now.isoformat())
            except Exception as e:
                logger.warning(f"Failed to mark key in Redis: {e}")

    async def cleanup_local_cache(self) -> int:
        """Remove expired entries from local cache.
        
        Returns:
            Number of entries removed
        """
        now = datetime.now(timezone.utc)
        expired_keys = [
            key for key, timestamp in self._local_cache.items()
            if now - timestamp >= self.ttl
        ]
        
        for key in expired_keys:
            del self._local_cache[key]
        
        logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")
        return len(expired_keys)

    def get_stats(self) -> dict[str, Any]:
        """Get deduplication statistics."""
        return {
            "local_cache_size": len(self._local_cache),
            "ttl_hours": self.ttl / timedelta(hours=1),
            "policy_version": self.policy_version,
            "redis_connected": self.redis is not None,
        }
