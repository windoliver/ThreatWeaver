"""
Notification service for approval requests.

This module handles sending notifications via multiple channels:
- Slack (webhook)
- Email (SMTP)
- In-app notifications (future)

Configuration:
Set these environment variables:
- SLACK_WEBHOOK_URL: Slack webhook URL for notifications
- SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD: Email settings
- EMAIL_FROM: Sender email address
"""

import logging
from typing import Optional

import httpx
from pydantic import BaseModel

from src.db.models.approval import ApprovalRequest

logger = logging.getLogger(__name__)


class NotificationService:
    """Service for sending notifications about approval requests."""

    @staticmethod
    async def send_approval_notification(
        approval: ApprovalRequest,
        slack_webhook_url: Optional[str] = None,
    ) -> bool:
        """
        Send notification when new approval request is created.

        Args:
            approval: ApprovalRequest to notify about
            slack_webhook_url: Optional Slack webhook URL (otherwise uses env var)

        Returns:
            True if notification sent successfully

        Example:
            >>> await send_approval_notification(approval, slack_webhook_url="https://...")
        """
        success = True

        # Send Slack notification
        if slack_webhook_url:
            slack_sent = await NotificationService._send_slack_notification(
                approval=approval,
                webhook_url=slack_webhook_url,
            )
            success = success and slack_sent

        # TODO: Send email notification
        # email_sent = await NotificationService._send_email_notification(approval)
        # success = success and email_sent

        return success

    @staticmethod
    async def send_decision_notification(
        approval: ApprovalRequest,
        slack_webhook_url: Optional[str] = None,
    ) -> bool:
        """
        Send notification when approval is approved/rejected.

        Args:
            approval: ApprovalRequest that was reviewed
            slack_webhook_url: Optional Slack webhook URL

        Returns:
            True if notification sent successfully
        """
        success = True

        # Send Slack notification
        if slack_webhook_url:
            slack_sent = await NotificationService._send_slack_decision_notification(
                approval=approval,
                webhook_url=slack_webhook_url,
            )
            success = success and slack_sent

        return success

    @staticmethod
    async def _send_slack_notification(
        approval: ApprovalRequest,
        webhook_url: str,
    ) -> bool:
        """
        Send Slack notification for new approval request.

        Args:
            approval: ApprovalRequest to notify about
            webhook_url: Slack webhook URL

        Returns:
            True if sent successfully
        """
        try:
            # Format Slack message
            message = {
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"🔔 New Approval Request: {approval.title}",
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Type:*\n{approval.request_type}",
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Risk Level:*\n{approval.risk_level}",
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Scan ID:*\n{approval.scan_id}",
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Expires:*\n{approval.expires_at.strftime('%Y-%m-%d %H:%M UTC') if approval.expires_at else 'No expiry'}",
                            },
                        ],
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Description:*\n{approval.description}",
                        },
                    },
                    {
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "text": "Review in Dashboard",
                                },
                                "url": f"https://app.threatweaver.com/approvals/{approval.id}",
                                "style": "primary",
                            },
                        ],
                    },
                ]
            }

            # Send to Slack
            async with httpx.AsyncClient() as client:
                response = await client.post(webhook_url, json=message, timeout=10.0)
                response.raise_for_status()

            logger.info(f"Sent Slack notification for approval {approval.id}")
            return True

        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")
            return False

    @staticmethod
    async def _send_slack_decision_notification(
        approval: ApprovalRequest,
        webhook_url: str,
    ) -> bool:
        """
        Send Slack notification for approval decision.

        Args:
            approval: ApprovalRequest that was reviewed
            webhook_url: Slack webhook URL

        Returns:
            True if sent successfully
        """
        try:
            # Determine emoji and color
            if approval.status == "approved":
                emoji = "✅"
                color = "good"
                decision_text = "APPROVED"
            elif approval.status == "rejected":
                emoji = "❌"
                color = "danger"
                decision_text = f"REJECTED: {approval.rejection_reason}"
            else:
                emoji = "⏰"
                color = "warning"
                decision_text = "EXPIRED"

            # Format Slack message
            message = {
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"{emoji} Approval {decision_text}: {approval.title}",
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Type:*\n{approval.request_type}",
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Status:*\n{approval.status.upper()}",
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Scan ID:*\n{approval.scan_id}",
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Reviewed At:*\n{approval.approved_at.strftime('%Y-%m-%d %H:%M UTC') if approval.approved_at else 'N/A'}",
                            },
                        ],
                    },
                ]
            }

            # Send to Slack
            async with httpx.AsyncClient() as client:
                response = await client.post(webhook_url, json=message, timeout=10.0)
                response.raise_for_status()

            logger.info(f"Sent Slack decision notification for approval {approval.id}")
            return True

        except Exception as e:
            logger.error(f"Failed to send Slack decision notification: {e}")
            return False

    # TODO: Implement email notifications
    # @staticmethod
    # async def _send_email_notification(approval: ApprovalRequest) -> bool:
    #     """Send email notification for approval request."""
    #     pass


# Convenience functions
async def send_approval_notification(
    approval: ApprovalRequest,
    slack_webhook_url: Optional[str] = None,
) -> bool:
    """Send notification when new approval request is created (convenience function)."""
    return await NotificationService.send_approval_notification(
        approval=approval,
        slack_webhook_url=slack_webhook_url,
    )


async def send_decision_notification(
    approval: ApprovalRequest,
    slack_webhook_url: Optional[str] = None,
) -> bool:
    """Send notification when approval is reviewed (convenience function)."""
    return await NotificationService.send_decision_notification(
        approval=approval,
        slack_webhook_url=slack_webhook_url,
    )
