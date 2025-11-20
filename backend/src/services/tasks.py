"""
Background tasks for ThreatWeaver.

This module contains background tasks that should be run periodically:
- mark_expired_approvals: Mark approval requests as expired (every 5 minutes)

Usage:
    # Run from command line
    python -m src.services.tasks

    # Or import and schedule with APScheduler, Celery, etc.
    from src.services.tasks import mark_expired_approvals_task
    scheduler.add_job(mark_expired_approvals_task, 'interval', minutes=5)
"""

import asyncio
import logging
from datetime import datetime

from src.db.session import AsyncSessionLocal
from src.services.approval import ApprovalService

logger = logging.getLogger(__name__)


async def mark_expired_approvals_task() -> int:
    """
    Mark expired approval requests as EXPIRED.

    This task should be run periodically (e.g., every 5 minutes) to ensure
    that pending approvals that have passed their expiry time are marked as expired.

    Returns:
        Number of approvals marked as expired
    """
    logger.info("Running mark_expired_approvals_task...")

    try:
        async with AsyncSessionLocal() as db:
            count = await ApprovalService.mark_expired_approvals(db)

            if count > 0:
                logger.info(f"Marked {count} approval(s) as expired")
            else:
                logger.debug("No expired approvals found")

            return count

    except Exception as e:
        logger.error(f"Error in mark_expired_approvals_task: {e}", exc_info=True)
        return 0


async def run_all_tasks():
    """Run all background tasks once (for testing)."""
    logger.info("Running all background tasks...")

    # Mark expired approvals
    expired_count = await mark_expired_approvals_task()

    logger.info(
        f"Background tasks completed. Expired approvals: {expired_count}"
    )


async def run_scheduler():
    """
    Run background tasks on a schedule.

    This is a simple scheduler that runs tasks in an infinite loop.
    In production, consider using APScheduler, Celery Beat, or similar.

    Schedule:
    - mark_expired_approvals: Every 5 minutes
    """
    logger.info("Starting background task scheduler...")

    while True:
        try:
            # Run mark_expired_approvals every 5 minutes
            await mark_expired_approvals_task()

            # Sleep for 5 minutes
            await asyncio.sleep(5 * 60)

        except Exception as e:
            logger.error(f"Error in scheduler: {e}", exc_info=True)
            # Sleep for 1 minute on error to avoid tight loop
            await asyncio.sleep(60)


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Run scheduler
    asyncio.run(run_scheduler())
