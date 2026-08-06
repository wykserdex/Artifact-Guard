"""Main entry point for Artifact Guard service."""

import asyncio
import signal

from shared.logging import setup_logging, get_logger
from shared.config import config

logger = get_logger(__name__)


async def main():
    """Main application entry point."""
    
    # Setup logging
    setup_logging(config.log_level, config.log_format)
    
    logger.info(
        "artifact_guard_starting",
        version="0.1.0",
        log_level=config.log_level,
        enable_active_analysis=config.enable_active_analysis,
    )
    
    # Initialize components
    # - Broker consumer/producer
    # - Database connection
    # - Analysis pipeline
    # - API server
    
    # TODO: Initialize Redis broker
    # TODO: Initialize PostgreSQL connection
    # TODO: Initialize analysis pipeline with analyzers
    # TODO: Start API server
    
    logger.info("artifact_guard_started")
    
    # Keep running until shutdown signal
    shutdown_event = asyncio.Event()
    
    def handle_signal():
        logger.info("shutdown_signal_received")
        shutdown_event.set()
    
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, handle_signal)
    
    await shutdown_event.wait()
    
    logger.info("artifact_guard_shutdown_complete")


if __name__ == "__main__":
    asyncio.run(main())
