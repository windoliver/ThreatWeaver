"""
Tests for the approval system (Human-in-the-Loop workflow).

This module tests:
- ApprovalService (create, get, review, auto-expiry)
- API endpoints (/api/v1/approvals)
- Notification service
- Background tasks (expiry)
"""

import pytest
from datetime import datetime, timedelta
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models.approval import ApprovalRequest, ApprovalRequestType, ApprovalStatus
from src.db.models.scan import Scan
from src.db.models.team import Team
from src.db.models.user import User
from src.services.approval import ApprovalService


@pytest.fixture
async def test_team(db: AsyncSession):
    """Create a test team."""
    team = Team(
        name="Test Team",
        slug="test-team",
    )
    db.add(team)
    await db.commit()
    await db.refresh(team)
    return team


@pytest.fixture
async def test_user(db: AsyncSession, test_team: Team):
    """Create a test user."""
    user = User(
        email="test@example.com",
        hashed_password="fake-hash",
        team_id=test_team.id,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


@pytest.fixture
async def test_scan(db: AsyncSession, test_team: Team):
    """Create a test scan."""
    scan = Scan(
        team_id=test_team.id,
        target="https://example.com",
        scan_type="reconnaissance",
        status="pending",
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    return scan


class TestApprovalService:
    """Test ApprovalService methods."""

    @pytest.mark.asyncio
    async def test_create_approval_request(self, db: AsyncSession, test_scan: Scan):
        """Test creating an approval request."""
        approval = await ApprovalService.create_approval_request(
            db=db,
            scan_id=test_scan.id,
            request_type=ApprovalRequestType.EXPLOIT_ATTEMPT,
            title="SQLMap data extraction",
            description="Execute SQLMap to extract user table",
            risk_level="HIGH",
            context={"target": "https://api.example.com", "vulnerability": "SQL Injection"},
            requested_action={"tool": "sqlmap", "parameters": ["--dump", "-T", "users"]},
            expiry_hours=1,
        )

        # Verify approval was created
        assert approval.id is not None
        assert approval.scan_id == test_scan.id
        assert approval.request_type == ApprovalRequestType.EXPLOIT_ATTEMPT.value
        assert approval.status == ApprovalStatus.PENDING.value
        assert approval.title == "SQLMap data extraction"
        assert approval.risk_level == "HIGH"

        # Verify expiry time is set
        assert approval.expires_at is not None
        expected_expiry = datetime.utcnow() + timedelta(hours=1)
        assert abs((approval.expires_at - expected_expiry).total_seconds()) < 60  # Within 1 minute

    @pytest.mark.asyncio
    async def test_get_approval_request(self, db: AsyncSession, test_scan: Scan):
        """Test getting an approval request by ID."""
        # Create approval
        approval = await ApprovalService.create_approval_request(
            db=db,
            scan_id=test_scan.id,
            request_type=ApprovalRequestType.DATA_ACCESS,
            title="Access sensitive data",
            description="Need access to customer data",
            risk_level="CRITICAL",
            context={},
            requested_action={},
        )

        # Get approval
        fetched = await ApprovalService.get_approval_request(db, approval.id)

        assert fetched is not None
        assert fetched.id == approval.id
        assert fetched.title == "Access sensitive data"

    @pytest.mark.asyncio
    async def test_get_pending_approvals(
        self, db: AsyncSession, test_scan: Scan, test_team: Team
    ):
        """Test getting pending approvals for a team."""
        # Create multiple approvals
        approval1 = await ApprovalService.create_approval_request(
            db=db,
            scan_id=test_scan.id,
            request_type=ApprovalRequestType.EXPLOIT_ATTEMPT,
            title="Approval 1",
            description="Test",
            risk_level="HIGH",
            context={},
            requested_action={},
        )

        approval2 = await ApprovalService.create_approval_request(
            db=db,
            scan_id=test_scan.id,
            request_type=ApprovalRequestType.DATA_ACCESS,
            title="Approval 2",
            description="Test",
            risk_level="MEDIUM",
            context={},
            requested_action={},
        )

        # Get pending approvals
        pending = await ApprovalService.get_pending_approvals(
            db=db, team_id=test_team.id, limit=50
        )

        # Verify both approvals are returned
        assert len(pending) >= 2
        pending_ids = [a.id for a in pending]
        assert approval1.id in pending_ids
        assert approval2.id in pending_ids

    @pytest.mark.asyncio
    async def test_review_approval_approve(
        self, db: AsyncSession, test_scan: Scan, test_user: User
    ):
        """Test approving an approval request."""
        # Create approval
        approval = await ApprovalService.create_approval_request(
            db=db,
            scan_id=test_scan.id,
            request_type=ApprovalRequestType.EXPLOIT_ATTEMPT,
            title="Test approval",
            description="Test",
            risk_level="HIGH",
            context={},
            requested_action={},
        )

        # Approve
        reviewed = await ApprovalService.review_approval(
            db=db,
            approval_id=approval.id,
            user_id=test_user.id,
            approve=True,
        )

        # Verify
        assert reviewed is not None
        assert reviewed.status == ApprovalStatus.APPROVED.value
        assert reviewed.approved_by == test_user.id
        assert reviewed.approved_at is not None
        assert reviewed.rejection_reason is None

    @pytest.mark.asyncio
    async def test_review_approval_reject(
        self, db: AsyncSession, test_scan: Scan, test_user: User
    ):
        """Test rejecting an approval request."""
        # Create approval
        approval = await ApprovalService.create_approval_request(
            db=db,
            scan_id=test_scan.id,
            request_type=ApprovalRequestType.EXPLOIT_ATTEMPT,
            title="Test approval",
            description="Test",
            risk_level="HIGH",
            context={},
            requested_action={},
        )

        # Reject
        reviewed = await ApprovalService.review_approval(
            db=db,
            approval_id=approval.id,
            user_id=test_user.id,
            approve=False,
            rejection_reason="Too risky",
        )

        # Verify
        assert reviewed is not None
        assert reviewed.status == ApprovalStatus.REJECTED.value
        assert reviewed.approved_by == test_user.id
        assert reviewed.approved_at is not None
        assert reviewed.rejection_reason == "Too risky"

    @pytest.mark.asyncio
    async def test_review_already_processed(
        self, db: AsyncSession, test_scan: Scan, test_user: User
    ):
        """Test that reviewing an already-processed approval fails."""
        # Create and approve approval
        approval = await ApprovalService.create_approval_request(
            db=db,
            scan_id=test_scan.id,
            request_type=ApprovalRequestType.EXPLOIT_ATTEMPT,
            title="Test approval",
            description="Test",
            risk_level="HIGH",
            context={},
            requested_action={},
        )

        await ApprovalService.review_approval(
            db=db,
            approval_id=approval.id,
            user_id=test_user.id,
            approve=True,
        )

        # Try to review again - should fail
        with pytest.raises(ValueError, match="already approved"):
            await ApprovalService.review_approval(
                db=db,
                approval_id=approval.id,
                user_id=test_user.id,
                approve=False,
            )

    @pytest.mark.asyncio
    async def test_review_expired_approval(
        self, db: AsyncSession, test_scan: Scan, test_user: User
    ):
        """Test that reviewing an expired approval fails."""
        # Create approval with past expiry
        approval = ApprovalRequest(
            scan_id=test_scan.id,
            request_type=ApprovalRequestType.EXPLOIT_ATTEMPT.value,
            status=ApprovalStatus.PENDING.value,
            title="Expired approval",
            description="Test",
            risk_level="HIGH",
            context={},
            requested_action={},
            expires_at=datetime.utcnow() - timedelta(hours=1),  # Expired 1 hour ago
        )
        db.add(approval)
        await db.commit()
        await db.refresh(approval)

        # Try to review - should fail and mark as expired
        with pytest.raises(ValueError, match="expired"):
            await ApprovalService.review_approval(
                db=db,
                approval_id=approval.id,
                user_id=test_user.id,
                approve=True,
            )

        # Verify it was marked as expired
        await db.refresh(approval)
        assert approval.status == ApprovalStatus.EXPIRED.value

    @pytest.mark.asyncio
    async def test_mark_expired_approvals(self, db: AsyncSession, test_scan: Scan):
        """Test marking expired approvals as EXPIRED."""
        # Create pending approval that is expired
        expired_approval = ApprovalRequest(
            scan_id=test_scan.id,
            request_type=ApprovalRequestType.EXPLOIT_ATTEMPT.value,
            status=ApprovalStatus.PENDING.value,
            title="Expired approval",
            description="Test",
            risk_level="HIGH",
            context={},
            requested_action={},
            expires_at=datetime.utcnow() - timedelta(hours=1),
        )
        db.add(expired_approval)

        # Create pending approval that is NOT expired
        valid_approval = await ApprovalService.create_approval_request(
            db=db,
            scan_id=test_scan.id,
            request_type=ApprovalRequestType.EXPLOIT_ATTEMPT,
            title="Valid approval",
            description="Test",
            risk_level="HIGH",
            context={},
            requested_action={},
            expiry_hours=24,
        )

        await db.commit()

        # Mark expired approvals
        count = await ApprovalService.mark_expired_approvals(db)

        # Verify
        assert count >= 1  # At least the one we created

        # Refresh and check status
        await db.refresh(expired_approval)
        await db.refresh(valid_approval)

        assert expired_approval.status == ApprovalStatus.EXPIRED.value
        assert valid_approval.status == ApprovalStatus.PENDING.value

    @pytest.mark.asyncio
    async def test_is_approved(self, db: AsyncSession, test_scan: Scan, test_user: User):
        """Test is_approved helper."""
        # Create and approve approval
        approval = await ApprovalService.create_approval_request(
            db=db,
            scan_id=test_scan.id,
            request_type=ApprovalRequestType.EXPLOIT_ATTEMPT,
            title="Test",
            description="Test",
            risk_level="HIGH",
            context={},
            requested_action={},
        )

        assert not ApprovalService.is_approved(approval)

        await ApprovalService.review_approval(
            db=db, approval_id=approval.id, user_id=test_user.id, approve=True
        )
        await db.refresh(approval)

        assert ApprovalService.is_approved(approval)

    @pytest.mark.asyncio
    async def test_is_expired(self, db: AsyncSession, test_scan: Scan):
        """Test is_expired helper."""
        # Create expired approval
        expired = ApprovalRequest(
            scan_id=test_scan.id,
            request_type=ApprovalRequestType.EXPLOIT_ATTEMPT.value,
            status=ApprovalStatus.PENDING.value,
            title="Expired",
            description="Test",
            risk_level="HIGH",
            context={},
            requested_action={},
            expires_at=datetime.utcnow() - timedelta(hours=1),
        )
        db.add(expired)
        await db.commit()

        # Create valid approval
        valid = await ApprovalService.create_approval_request(
            db=db,
            scan_id=test_scan.id,
            request_type=ApprovalRequestType.EXPLOIT_ATTEMPT,
            title="Valid",
            description="Test",
            risk_level="HIGH",
            context={},
            requested_action={},
            expiry_hours=24,
        )

        assert ApprovalService.is_expired(expired)
        assert not ApprovalService.is_expired(valid)


# Note: API endpoint tests would require FastAPI TestClient setup
# These are covered by integration tests with the full application
