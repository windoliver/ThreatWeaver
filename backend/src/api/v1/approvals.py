"""
API endpoints for approval requests (Human-in-the-Loop workflow).

Endpoints:
- POST /api/v1/approvals - Create approval request
- GET /api/v1/approvals - List all approvals for team
- GET /api/v1/approvals/pending - List pending approvals for team
- GET /api/v1/approvals/{id} - Get approval request details
- POST /api/v1/approvals/{id}/review - Approve or reject request
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.schemas.approval import (
    ApprovalRequestCreate,
    ApprovalRequestList,
    ApprovalRequestResponse,
    ApprovalReview,
    enrich_approval_response,
)
from src.db.models.approval import ApprovalStatus
from src.db.models.user import User
from src.db.session import get_async_db
from src.security.dependencies import get_current_active_user
from src.services.approval import ApprovalService

router = APIRouter(prefix="/approvals", tags=["approvals"])


@router.post(
    "",
    response_model=ApprovalRequestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create approval request",
    description="Create a new approval request for HITL workflow (exploitation, data access, etc.)",
)
async def create_approval(
    approval_data: ApprovalRequestCreate,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user),
):
    """
    Create a new approval request.

    This endpoint is typically called by agents when they need human approval
    for sensitive operations like:
    - Exploit attempts (SQLMap, Metasploit)
    - Data extraction
    - Shell access
    - Destructive operations

    The request will expire after the specified number of hours (default: 1).
    """
    # Create approval request
    approval = await ApprovalService.create_approval_request(
        db=db,
        scan_id=approval_data.scan_id,
        request_type=approval_data.request_type,
        title=approval_data.title,
        description=approval_data.description,
        risk_level=approval_data.risk_level,
        context=approval_data.context,
        requested_action=approval_data.requested_action,
        expiry_hours=approval_data.expiry_hours,
    )

    # TODO: Send notification (Slack, email)
    # await send_approval_notification(approval)

    return enrich_approval_response(approval)


@router.get(
    "",
    response_model=ApprovalRequestList,
    summary="List all approvals for team",
    description="Get all approval requests for the current user's team (paginated)",
)
async def list_approvals(
    status_filter: Optional[str] = None,
    limit: int = 100,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user),
):
    """
    List all approval requests for the current user's team.

    Optionally filter by status: pending, approved, rejected, expired.
    """
    # Parse status filter
    approval_status = None
    if status_filter:
        try:
            approval_status = ApprovalStatus(status_filter)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status: {status_filter}. Must be one of: pending, approved, rejected, expired",
            )

    # Get approvals for team
    approvals = await ApprovalService.get_all_approvals(
        db=db,
        team_id=current_user.team_id,
        status=approval_status,
        limit=limit,
    )

    # Enrich responses
    enriched_approvals = [enrich_approval_response(a) for a in approvals]

    return ApprovalRequestList(
        approvals=enriched_approvals,
        total=len(enriched_approvals),
    )


@router.get(
    "/pending",
    response_model=ApprovalRequestList,
    summary="List pending approvals",
    description="Get all pending approval requests for the current user's team",
)
async def list_pending_approvals(
    limit: int = 50,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user),
):
    """
    List pending approval requests for the current user's team.

    These are approvals that:
    - Have status = "pending"
    - Have not expired
    - Belong to scans owned by the user's team
    """
    # Get pending approvals
    approvals = await ApprovalService.get_pending_approvals(
        db=db,
        team_id=current_user.team_id,
        limit=limit,
    )

    # Enrich responses
    enriched_approvals = [enrich_approval_response(a) for a in approvals]

    return ApprovalRequestList(
        approvals=enriched_approvals,
        total=len(enriched_approvals),
    )


@router.get(
    "/{approval_id}",
    response_model=ApprovalRequestResponse,
    summary="Get approval request details",
    description="Get details of a specific approval request",
)
async def get_approval(
    approval_id: int,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user),
):
    """
    Get details of a specific approval request.

    Returns 404 if the approval doesn't exist or doesn't belong to the user's team.
    """
    # Get approval
    approval = await ApprovalService.get_approval_request(db=db, approval_id=approval_id)

    if not approval:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Approval request {approval_id} not found",
        )

    # Check that approval belongs to user's team
    if approval.scan.team_id != current_user.team_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to view this approval request",
        )

    return enrich_approval_response(approval)


@router.post(
    "/{approval_id}/review",
    response_model=ApprovalRequestResponse,
    summary="Review approval request",
    description="Approve or reject an approval request",
)
async def review_approval_endpoint(
    approval_id: int,
    review_data: ApprovalReview,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user),
):
    """
    Review an approval request (approve or reject).

    Only users from the same team can review approval requests.
    Once reviewed, the agent will receive the decision and proceed or stop accordingly.

    Requirements:
    - Approval must be in "pending" status
    - Approval must not be expired
    - User must belong to the same team as the scan
    """
    # Get approval
    approval = await ApprovalService.get_approval_request(db=db, approval_id=approval_id)

    if not approval:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Approval request {approval_id} not found",
        )

    # Check that approval belongs to user's team
    if approval.scan.team_id != current_user.team_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to review this approval request",
        )

    # Validate rejection reason
    if not review_data.approve and not review_data.rejection_reason:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="rejection_reason is required when rejecting an approval",
        )

    # Review approval
    try:
        reviewed_approval = await ApprovalService.review_approval(
            db=db,
            approval_id=approval_id,
            user_id=current_user.id,
            approve=review_data.approve,
            rejection_reason=review_data.rejection_reason,
        )

        if not reviewed_approval:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Approval request {approval_id} not found",
            )

        # TODO: Send notification to agent/scan about decision
        # await notify_approval_decision(reviewed_approval)

        return enrich_approval_response(reviewed_approval)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
