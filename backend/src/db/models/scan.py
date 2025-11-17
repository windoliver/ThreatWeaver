"""Scan model for security assessments."""

from enum import Enum
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..base import Base, TimestampMixin

if TYPE_CHECKING:
    from .approval import ApprovalRequest
    from .finding import Finding
    from .team import Team


class ScanStatus(str, Enum):
    """Status of a security scan."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(str, Enum):
    """Type of security scan."""

    FULL = "full"  # Both recon and assessment
    RECON_ONLY = "recon_only"  # Reconnaissance only
    ASSESSMENT_ONLY = "assessment_only"  # Assessment only (requires prior recon)


class Scan(Base, TimestampMixin):
    """Scan model representing a security assessment."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    team_id: Mapped[int] = mapped_column(
        ForeignKey("teams.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    target: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    scan_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default=ScanType.FULL.value,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default=ScanStatus.PENDING.value,
        index=True,
    )

    # Scan configuration and results stored as JSON
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    recon_results: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    assessment_results: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    agent_logs: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    # Error tracking
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    team: Mapped["Team"] = relationship("Team", back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(
        "Finding",
        back_populates="scan",
        cascade="all, delete-orphan",
    )
    approval_requests: Mapped[list["ApprovalRequest"]] = relationship(
        "ApprovalRequest",
        back_populates="scan",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Scan(id={self.id}, name={self.name}, status={self.status}, target={self.target})>"
