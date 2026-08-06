"""Renderer worker for processing browser rendering tasks."""

import asyncio
from shared.logging import setup_logging, get_logger
from shared.config import config

logger = get_logger(__name__)


async def process_render_task(task: dict) -> dict:
    """Process a single render task."""
    from renderer.browser import render_page
    
    url = task.get("url")
    analysis_id = task.get("analysis_id")
    
    logger.info("render_task_started", analysis_id=analysis_id, url=url)
    
    try:
        result = await render_page(
            url=url,
            timeout_ms=config.renderer_timeout_ms,
            viewport_width=config.renderer_viewport_width,
            viewport_height=config.renderer_viewport_height,
            max_redirects=config.renderer_max_redirects,
        )
        
        logger.info(
            "render_task_completed",
            analysis_id=analysis_id,
            final_url=result.final_url,
            redirect_count=len(result.redirects),
            html_size=len(result.html),
        )
        
        return {
            "status": "success",
            "analysis_id": analysis_id,
            "final_url": result.final_url,
            "title": result.title,
            "redirects": result.redirects,
            "forms_detected": len(result.forms) if result.forms else 0,
            "javascript_detected": result.javascript_detected,
            # Note: screenshot and html are stored separately in object storage
        }
        
    except TimeoutError as e:
        logger.warning("render_task_timeout", analysis_id=analysis_id, url=url)
        return {
            "status": "error",
            "analysis_id": analysis_id,
            "error_type": "timeout",
            "error_message": "Page load timed out",
        }
        
    except Exception as e:
        logger.exception("render_task_error", analysis_id=analysis_id, error=str(e))
        return {
            "status": "error",
            "analysis_id": analysis_id,
            "error_type": type(e).__name__,
            "error_message": str(e),
        }


async def main():
    """Main worker loop."""
    
    setup_logging(config.log_level, config.log_format)
    
    logger.info("renderer_worker_starting")
    
    # TODO: Connect to broker and listen for render tasks
    # For now, just log that we're ready
    
    logger.info("renderer_worker_ready")
    
    # Keep running
    shutdown_event = asyncio.Event()
    await shutdown_event.wait()


if __name__ == "__main__":
    asyncio.run(main())
