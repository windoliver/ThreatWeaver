"""Security event model for tracking security incidents and audit logs."""

from enum import Enum
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..base import Base, TimestampMixin

if TYPE_CHECKING:
    from .team import Team
    from .user import User


class SecurityEventType(str, Enum):
    """Type of security event."""

    PROMPT_INJECTION_ATTEMPT = "prompt_injection_attempt"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    SCOPE_VALIDATION_FAILURE = "scope_validation_failure"
    TOOL_EXECUTION_BLOCKED = "tool_execution_blocked"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"


class ThreatLevel(str, Enum):
    """Threat level for security events."""

    DANGEROUS = "dangerous"
    WARNING = "warning"
    INFO = "info"


class SecurityEvent(Base, TimestampMixin):
    """Security event or audit log entry."""

    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    # Event identification
    event_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )
    threat_level: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )

    # Context
    team_id: Mapped[int | None] = mapped_column(
        ForeignKey("teams.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Event details
    description: Mapped[str] = mapped_column(Text, nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)  # IPv6 compatible
    user_agent: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Additional metadata stored as JSON
    event_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Matched patterns (for prompt injection events)
    matched_patterns: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    # Original input (for investigation)
    input_text: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    team: Mapped["Team | None"] = relationship("Team", back_populates="security_events")
    user: Mapped["User | None"] = relationship("User", back_populates="security_events")

    def __repr__(self) -> str:
        return (
            f"<SecurityEvent(id={self.id}, type={self.event_type}, "
            f"threat_level={self.threat_level}, team_id={self.team_id})>"
        )
