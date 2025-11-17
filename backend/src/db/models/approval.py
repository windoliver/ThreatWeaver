"""ApprovalRequest model for Human-in-the-Loop workflow."""

from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..base import Base, TimestampMixin

if TYPE_CHECKING:
    from .scan import Scan


class ApprovalStatus(str, Enum):
    """Status of an approval request."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class ApprovalRequestType(str, Enum):
    """Type of approval request."""

    TOOL_EXECUTION = "tool_execution"  # Approval to execute a security tool
    VULNERABILITY_SCAN = "vulnerability_scan"  # Approval for vulnerability scanning
    EXPLOIT_ATTEMPT = "exploit_attempt"  # Approval for exploitation (in authorized context)
    DATA_ACCESS = "data_access"  # Approval to access sensitive data
    CUSTOM = "custom"  # Custom approval request


class ApprovalRequest(Base, TimestampMixin):
    """Approval request for Human-in-the-Loop (HITL) workflow."""

    __tablename__ = "approval_requests"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    request_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default=ApprovalStatus.PENDING.value,
        index=True,
    )

    # Request details
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(50), nullable=False)

    # Context and parameters
    context: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    requested_action: Mapped[dict] = mapped_column(JSONB, nullable=False)

    # Approval tracking
    approved_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    approved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Expiration
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="approval_requests")

    def __repr__(self) -> str:
        return (
            f"<ApprovalRequest(id={self.id}, type={self.request_type}, "
            f"status={self.status}, scan_id={self.scan_id})>"
        )
