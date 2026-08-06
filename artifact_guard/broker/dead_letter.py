"""Dead letter queue handler for failed messages."""

import asyncio
from datetime import datetime, timezone
from typing import Callable

import redis.asyncio as redis

from shared.logging import get_logger

logger = get_logger(__name__)


class DeadLetterHandler:
    """Handles messages from dead letter queue."""

    def __init__(
        self,
        redis_url: str,
        dead_letter_stream: str = "artifact.dead_letter",
        max_retries: int = 3,
    ):
        self.redis_url = redis_url
        self.dead_letter_stream = dead_letter_stream
        self.max_retries = max_retries
        self.redis: redis.Redis | None = None
        self._running = False

    async def connect(self) -> None:
        """Connect to Redis."""
        self.redis = redis.from_url(
            self.redis_url,
            encoding="utf-8",
            decode_responses=True,
        )
        logger.info("Connected to Redis for dead letter handling")

    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self.redis:
            await self.redis.close()
            self.redis = None

    async def process_dead_letter(
        self,
        message_id: bytes,
        data: dict[str, str],
        retry_handler: Callable | None = None,
    ) -> bool:
        """Process a single dead letter message.
        
        Args:
            message_id: ID of the dead letter message
            data: Message data
            retry_handler: Optional handler to retry the original operation
            
        Returns:
            True if message should be deleted, False if it should be kept
        """
        reason = data.get("dead_letter_reason", "Unknown")
        source = data.get("dead_letter_source", "Unknown")
        retry_count = int(data.get("retry_count", "0"))

        logger.warning(
            f"Processing dead letter {message_id}: {reason} "
            f"(from {source}, retry {retry_count}/{self.max_retries})"
        )

        # Check if we can retry
        if retry_count < self.max_retries and retry_handler:
            try:
                # Attempt to retry the original operation
                success = await retry_handler(data)
                if success:
                    logger.info(f"Successfully retried dead letter {message_id}")
                    return True  # Delete from dead letter
            except Exception as e:
                logger.error(f"Retry failed for {message_id}: {e}")

        # Update retry count
        new_retry_count = retry_count + 1
        await self.redis.xpending(
            self.dead_letter_stream,
            "artifact_guard_group",
            min=message_id,
            max=message_id,
            count=1,
        )

        # Mark for manual review if max retries exceeded
        if new_retry_count >= self.max_retries:
            logger.error(
                f"Message {message_id} exceeded max retries, "
                f"requires manual review"
            )
            # Keep in dead letter for manual inspection
            return False

        # Update retry count in message
        await self.redis.xadd(
            self.dead_letter_stream,
            {
                **data,
                "retry_count": str(new_retry_count),
                "last_retry_at": datetime.now(timezone.utc).isoformat(),
            },
            messageID=message_id,
        )

        return False  # Keep in dead letter

    async def consume_dead_letters(
        self,
        retry_handler: Callable | None = None,
        batch_size: int = 10,
        block_timeout: int = 10000,
    ) -> None:
        """Consume and process dead letter messages.
        
        Args:
            retry_handler: Optional handler to retry operations
            batch_size: Number of messages to process per iteration
            block_timeout: Timeout in ms to block waiting for messages
        """
        if not self.redis:
            raise RuntimeError("Not connected to Redis")

        self._running = True
        logger.info(f"Starting dead letter consumption from {self.dead_letter_stream}")

        while self._running:
            try:
                # Read pending messages
                pending = await self.redis.xpending_range(
                    self.dead_letter_stream,
                    "artifact_guard_group",
                    min="-",
                    max="+",
                    count=batch_size,
                )

                if not pending:
                    # No pending messages, wait for new ones
                    messages = await self.redis.xreadgroup(
                        groupname="artifact_guard_group",
                        consumername="dead_letter_worker",
                        streams={self.dead_letter_stream: ">"},
                        count=batch_size,
                        block=block_timeout,
                    )

                    if not messages:
                        continue

                    for stream_name, stream_messages in messages:
                        for message_id, data in stream_messages:
                            should_delete = await self.process_dead_letter(
                                message_id, data, retry_handler
                            )
                            if should_delete:
                                await self.redis.xack(
                                    self.dead_letter_stream,
                                    "artifact_guard_group",
                                    message_id,
                                )
                else:
                    # Process pending messages
                    for item in pending:
                        message_id = item["message_id"]
                        # Fetch full message data
                        messages = await self.redis.xrange(
                            self.dead_letter_stream,
                            min=message_id,
                            max=message_id,
                        )
                        if messages:
                            _, data = messages[0]
                            should_delete = await self.process_dead_letter(
                                message_id.encode(), data, retry_handler
                            )
                            if should_delete:
                                await self.redis.xack(
                                    self.dead_letter_stream,
                                    "artifact_guard_group",
                                    message_id.encode(),
                                )

            except Exception as e:
                logger.error(f"Error in dead letter processing: {e}")
                await asyncio.sleep(1)

    def stop(self) -> None:
        """Stop the dead letter processing loop."""
        self._running = False
