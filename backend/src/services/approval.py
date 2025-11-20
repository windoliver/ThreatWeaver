"""
Approval service for Human-in-the-Loop (HITL) workflow.

This module provides functions to create, retrieve, and review approval requests
for security-sensitive operations like exploitation and data access.

Architecture:
- request_approval(): Create approval request with 1-hour expiry
- get_pending_approvals(): Fetch pending approvals for a team
- review_approval(): Approve or reject a request
- Auto-expiry: Background task marks expired requests
"""

from datetime import datetime, timedelta
from typing import List, Optional

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.db.models.approval import (
    ApprovalRequest,
    ApprovalRequestType,
    ApprovalStatus,
)
from src.db.models.scan import Scan


class ApprovalService:
    """Service for managing approval requests."""

    DEFAULT_EXPIRY_HOURS = 1  # 1-hour expiry as per requirements

    @staticmethod
    async def create_approval_request(
        db: AsyncSession,
        scan_id: int,
        request_type: ApprovalRequestType,
        title: str,
        description: str,
        risk_level: str,
        context: dict,
        requested_action: dict,
        expiry_hours: int = DEFAULT_EXPIRY_HOURS,
    ) -> ApprovalRequest:
        """
        Create a new approval request.

        Args:
            db: Database session
            scan_id: ID of the scan requesting approval
            request_type: Type of approval (EXPLOIT_ATTEMPT, DATA_ACCESS, etc.)
            title: Short title for the approval request
            description: Detailed description of what needs approval
            risk_level: Risk level (LOW, MEDIUM, HIGH, CRITICAL)
            context: Additional context (target, vulnerability details, etc.)
            requested_action: The action being requested (tool, parameters, etc.)
            expiry_hours: Hours until auto-expiry (default: 1)

        Returns:
            Created ApprovalRequest

        Example:
            >>> approval = await create_approval_request(
            ...     db=db,
            ...     scan_id=123,
            ...     request_type=ApprovalRequestType.EXPLOIT_ATTEMPT,
            ...     title="SQLMap data extraction for /api/login",
            ...     description="Execute SQLMap to extract user table from database",
            ...     risk_level="HIGH",
            ...     context={
            ...         "target": "https://api.example.com/login",
            ...         "vulnerability": "SQL Injection",
            ...         "cvss_score": 8.5
            ...     },
            ...     requested_action={
            ...         "tool": "sqlmap",
            ...         "parameters": ["--dump", "-T", "users"]
            ...     }
            ... )
        """
        # Calculate expiry time
        expires_at = datetime.utcnow() + timedelta(hours=expiry_hours)

        # Create approval request
        approval = ApprovalRequest(
            scan_id=scan_id,
            request_type=request_type.value if isinstance(request_type, ApprovalRequestType) else request_type,
            status=ApprovalStatus.PENDING.value,
            title=title,
            description=description,
            risk_level=risk_level,
            context=context,
            requested_action=requested_action,
            expires_at=expires_at,
        )

        db.add(approval)
        await db.commit()
        await db.refresh(approval)

        return approval

    @staticmethod
    async def get_approval_request(
        db: AsyncSession,
        approval_id: int,
        load_scan: bool = True,
    ) -> Optional[ApprovalRequest]:
        """
        Get an approval request by ID.

        Args:
            db: Database session
            approval_id: Approval request ID
            load_scan: Whether to eagerly load the scan relationship

        Returns:
            ApprovalRequest or None if not found
        """
        query = select(ApprovalRequest).where(ApprovalRequest.id == approval_id)

        if load_scan:
            query = query.options(selectinload(ApprovalRequest.scan))

        result = await db.execute(query)
        return result.scalar_one_or_none()

    @staticmethod
    async def get_pending_approvals(
        db: AsyncSession,
        team_id: int,
        limit: int = 50,
    ) -> List[ApprovalRequest]:
        """
        Get pending approval requests for a team.

        Args:
            db: Database session
            team_id: Team ID to filter by
            limit: Maximum number of results

        Returns:
            List of pending ApprovalRequests
        """
        # Query pending approvals for scans belonging to this team
        query = (
            select(ApprovalRequest)
            .join(Scan)
            .where(
                and_(
                    ApprovalRequest.status == ApprovalStatus.PENDING.value,
                    Scan.team_id == team_id,
                )
            )
            .options(selectinload(ApprovalRequest.scan))
            .order_by(ApprovalRequest.created_at.desc())
            .limit(limit)
        )

        result = await db.execute(query)
        return list(result.scalars().all())

    @staticmethod
    async def get_all_approvals(
        db: AsyncSession,
        team_id: int,
        status: Optional[ApprovalStatus] = None,
        limit: int = 100,
    ) -> List[ApprovalRequest]:
        """
        Get all approval requests for a team (optionally filtered by status).

        Args:
            db: Database session
            team_id: Team ID to filter by
            status: Optional status filter
            limit: Maximum number of results

        Returns:
            List of ApprovalRequests
        """
        query = (
            select(ApprovalRequest)
            .join(Scan)
            .where(Scan.team_id == team_id)
        )

        if status:
            query = query.where(ApprovalRequest.status == status.value)

        query = (
            query.options(selectinload(ApprovalRequest.scan))
            .order_by(ApprovalRequest.created_at.desc())
            .limit(limit)
        )

        result = await db.execute(query)
        return list(result.scalars().all())

    @staticmethod
    async def review_approval(
        db: AsyncSession,
        approval_id: int,
        user_id: int,
        approve: bool,
        rejection_reason: Optional[str] = None,
    ) -> Optional[ApprovalRequest]:
        """
        Approve or reject an approval request.

        Args:
            db: Database session
            approval_id: Approval request ID
            user_id: ID of user making the decision
            approve: True to approve, False to reject
            rejection_reason: Reason for rejection (required if approve=False)

        Returns:
            Updated ApprovalRequest or None if not found

        Raises:
            ValueError: If approval is already processed or expired
        """
        # Get approval request
        approval = await ApprovalService.get_approval_request(db, approval_id, load_scan=False)

        if not approval:
            return None

        # Check if already processed
        if approval.status != ApprovalStatus.PENDING.value:
            raise ValueError(f"Approval already {approval.status}")

        # Check if expired
        if approval.expires_at and datetime.utcnow() > approval.expires_at:
            # Auto-expire
            approval.status = ApprovalStatus.EXPIRED.value
            await db.commit()
            await db.refresh(approval)
            raise ValueError("Approval request has expired")

        # Update approval
        if approve:
            approval.status = ApprovalStatus.APPROVED.value
            approval.approved_by = user_id
            approval.approved_at = datetime.utcnow()
        else:
            approval.status = ApprovalStatus.REJECTED.value
            approval.approved_by = user_id
            approval.approved_at = datetime.utcnow()
            approval.rejection_reason = rejection_reason or "No reason provided"

        await db.commit()
        await db.refresh(approval)

        return approval

    @staticmethod
    async def mark_expired_approvals(db: AsyncSession) -> int:
        """
        Mark expired pending approvals as EXPIRED.

        This should be run periodically (e.g., every 5 minutes) by a background task.

        Args:
            db: Database session

        Returns:
            Number of approvals marked as expired
        """
        # Find pending approvals that have expired
        query = select(ApprovalRequest).where(
            and_(
                ApprovalRequest.status == ApprovalStatus.PENDING.value,
                ApprovalRequest.expires_at < datetime.utcnow(),
            )
        )

        result = await db.execute(query)
        expired_approvals = list(result.scalars().all())

        # Mark as expired
        for approval in expired_approvals:
            approval.status = ApprovalStatus.EXPIRED.value

        if expired_approvals:
            await db.commit()

        return len(expired_approvals)

    @staticmethod
    def is_approved(approval: ApprovalRequest) -> bool:
        """Check if an approval request is approved."""
        return approval.status == ApprovalStatus.APPROVED.value

    @staticmethod
    def is_pending(approval: ApprovalRequest) -> bool:
        """Check if an approval request is pending."""
        return approval.status == ApprovalStatus.PENDING.value

    @staticmethod
    def is_expired(approval: ApprovalRequest) -> bool:
        """Check if an approval request is expired."""
        if approval.status == ApprovalStatus.EXPIRED.value:
            return True

        # Check if expiry time has passed
        if approval.expires_at and datetime.utcnow() > approval.expires_at:
            return True

        return False


# Convenience functions for direct use
async def create_approval_request(
    db: AsyncSession,
    scan_id: int,
    request_type: ApprovalRequestType,
    title: str,
    description: str,
    risk_level: str,
    context: dict,
    requested_action: dict,
    expiry_hours: int = ApprovalService.DEFAULT_EXPIRY_HOURS,
) -> ApprovalRequest:
    """Create a new approval request (convenience function)."""
    return await ApprovalService.create_approval_request(
        db=db,
        scan_id=scan_id,
        request_type=request_type,
        title=title,
        description=description,
        risk_level=risk_level,
        context=context,
        requested_action=requested_action,
        expiry_hours=expiry_hours,
    )


async def get_approval_request(
    db: AsyncSession,
    approval_id: int,
) -> Optional[ApprovalRequest]:
    """Get an approval request by ID (convenience function)."""
    return await ApprovalService.get_approval_request(db, approval_id)


async def get_pending_approvals(
    db: AsyncSession,
    team_id: int,
    limit: int = 50,
) -> List[ApprovalRequest]:
    """Get pending approvals for a team (convenience function)."""
    return await ApprovalService.get_pending_approvals(db, team_id, limit)


async def review_approval(
    db: AsyncSession,
    approval_id: int,
    user_id: int,
    approve: bool,
    rejection_reason: Optional[str] = None,
) -> Optional[ApprovalRequest]:
    """Review an approval request (convenience function)."""
    return await ApprovalService.review_approval(
        db=db,
        approval_id=approval_id,
        user_id=user_id,
        approve=approve,
        rejection_reason=rejection_reason,
    )
