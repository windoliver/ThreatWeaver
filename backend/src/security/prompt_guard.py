"""Prompt injection guardrails for protecting against malicious inputs."""

import re
from datetime import datetime
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import SecurityEvent, SecurityEventType, ThreatLevel


class SecurityError(Exception):
    """Exception raised when a security threat is detected."""

    pass


class PromptGuard:
    """Multi-layered defense against prompt injection attacks.

    Implements three layers of protection:
    1. Input sanitization - Pattern matching for known injection attempts
    2. Structured outputs - Enforced via Pydantic models (implemented at LLM call sites)
    3. Tool whitelisting - Agent-specific allowed tools (implemented in agent classes)
    """

    # Layer 1: Injection Pattern Detection
    # Format: (pattern, threat_level, description)
    INJECTION_PATTERNS = [
        # Direct instruction override attempts
        (
            r"ignore\s+(previous|all|above|prior)\s+(instructions?|prompts?|rules?|context)",
            ThreatLevel.DANGEROUS,
            "Direct instruction override",
        ),
        (
            r"disregard\s+(previous|all|above|prior)\s+(instructions?|prompts?|rules?)",
            ThreatLevel.DANGEROUS,
            "Instruction disregard attempt",
        ),
        (
            r"forget\s+(everything|all|your)\s+(previous|above|instructions?)",
            ThreatLevel.DANGEROUS,
            "Memory reset attempt",
        ),
        # Role manipulation
        (
            r"you\s+are\s+now\s+(a|an|my|the)",
            ThreatLevel.DANGEROUS,
            "Role hijacking attempt",
        ),
        (
            r"act\s+as\s+(a|an|my|the)",
            ThreatLevel.WARNING,
            "Role change request",
        ),
        (
            r"pretend\s+(to\s+be|you\s+are)",
            ThreatLevel.WARNING,
            "Impersonation attempt",
        ),
        # System message injection
        (
            r"<\|im_start\|>",
            ThreatLevel.DANGEROUS,
            "Control token injection (im_start)",
        ),
        (
            r"<\|im_end\|>",
            ThreatLevel.DANGEROUS,
            "Control token injection (im_end)",
        ),
        (
            r"<\|system\|>",
            ThreatLevel.DANGEROUS,
            "System message injection",
        ),
        (
            r"<\|assistant\|>",
            ThreatLevel.DANGEROUS,
            "Assistant message injection",
        ),
        # Prompt leaking
        (
            r"(print|show|display|reveal|output)\s+(your|the|me\s+your)\s+(system\s+)?(prompt|instructions?|initial\s+instructions?|message|original\s+prompt)",
            ThreatLevel.WARNING,
            "Prompt leaking attempt",
        ),
        (
            r"what\s+(is|are)\s+your\s+(initial|original|system)\s+(prompt|instructions?)",
            ThreatLevel.WARNING,
            "Prompt disclosure request",
        ),
        (
            r"reveal\s+your\s+(original|initial|system)\s+(prompt|instructions?)",
            ThreatLevel.WARNING,
            "Prompt reveal attempt",
        ),
        # Jailbreak attempts
        (
            r"DAN\s+mode",
            ThreatLevel.DANGEROUS,
            "DAN jailbreak attempt",
        ),
        (
            r"developer\s+mode",
            ThreatLevel.WARNING,
            "Developer mode activation",
        ),
        (
            r"sudo\s+mode",
            ThreatLevel.WARNING,
            "Sudo mode activation",
        ),
        # Malicious tool execution
        (
            r"execute\s+(malicious|harmful|dangerous)",
            ThreatLevel.DANGEROUS,
            "Malicious execution request",
        ),
        (
            r"rm\s+-rf\s+/",
            ThreatLevel.DANGEROUS,
            "Destructive command injection",
        ),
        (
            r"drop\s+table",
            ThreatLevel.DANGEROUS,
            "SQL injection attempt",
        ),
        # Data exfiltration
        (
            r"send\s+(all|everything|data|everything)\s+to\s+",
            ThreatLevel.DANGEROUS,
            "Data exfiltration attempt",
        ),
        (
            r"export\s+(all|everything|data)\s+to\s+",
            ThreatLevel.DANGEROUS,
            "Data export attempt",
        ),
        (
            r"send\s+all\s+data\s+to\s+",
            ThreatLevel.DANGEROUS,
            "Data exfiltration attempt",
        ),
        # Encoding bypass attempts
        (
            r"base64\s*\(",
            ThreatLevel.WARNING,
            "Base64 encoding (potential bypass)",
        ),
        (
            r"eval\s*\(",
            ThreatLevel.DANGEROUS,
            "Code evaluation attempt",
        ),
        (
            r"exec\s*\(",
            ThreatLevel.DANGEROUS,
            "Code execution attempt",
        ),
    ]

    @classmethod
    def analyze(cls, text: str) -> tuple[ThreatLevel, list[dict[str, str]]]:
        """Analyze text for prompt injection patterns.

        Args:
            text: User input to analyze

        Returns:
            Tuple of (highest_threat_level, matched_patterns)
            matched_patterns: List of dicts with 'pattern' and 'description'
        """
        if not text:
            return ThreatLevel.INFO, []

        # Normalize text for analysis (lowercase, preserve structure)
        normalized = text.lower()

        matched_patterns = []
        highest_threat = ThreatLevel.INFO

        for pattern, threat_level, description in cls.INJECTION_PATTERNS:
            if re.search(pattern, normalized, re.IGNORECASE | re.MULTILINE):
                matched_patterns.append({
                    "pattern": pattern,
                    "description": description,
                    "threat_level": threat_level.value,
                })

                # Update highest threat level
                if threat_level == ThreatLevel.DANGEROUS:
                    highest_threat = ThreatLevel.DANGEROUS
                elif threat_level == ThreatLevel.WARNING and highest_threat != ThreatLevel.DANGEROUS:
                    highest_threat = ThreatLevel.WARNING

        return highest_threat, matched_patterns

    @classmethod
    async def validate_user_input(
        cls,
        text: str,
        db: AsyncSession,
        team_id: Optional[int] = None,
        user_id: Optional[int] = None,
        source_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> str:
        """Validate user input and raise SecurityError if threats detected.

        Args:
            text: User input to validate
            db: Database session for logging
            team_id: Team ID for audit logging
            user_id: User ID for audit logging
            source_ip: Source IP address
            user_agent: User agent string

        Returns:
            Original text if safe

        Raises:
            SecurityError: If dangerous patterns detected
        """
        threat_level, matched_patterns = cls.analyze(text)

        # Log all non-INFO events
        if threat_level != ThreatLevel.INFO:
            await cls.log_security_event(
                db=db,
                event_type=SecurityEventType.PROMPT_INJECTION_ATTEMPT,
                threat_level=threat_level,
                description=f"Detected {len(matched_patterns)} injection pattern(s)",
                team_id=team_id,
                user_id=user_id,
                source_ip=source_ip,
                user_agent=user_agent,
                matched_patterns=matched_patterns,
                input_text=text,
            )

        # Block dangerous attempts
        if threat_level == ThreatLevel.DANGEROUS:
            raise SecurityError(
                f"Prompt injection detected. Matched {len(matched_patterns)} dangerous pattern(s). "
                "This incident has been logged."
            )

        # Allow warnings (log but don't block)
        return text

    @classmethod
    async def log_security_event(
        cls,
        db: AsyncSession,
        event_type: SecurityEventType,
        threat_level: ThreatLevel,
        description: str,
        team_id: Optional[int] = None,
        user_id: Optional[int] = None,
        source_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        matched_patterns: Optional[list[dict]] = None,
        input_text: Optional[str] = None,
        event_metadata: Optional[dict] = None,
    ) -> SecurityEvent:
        """Log a security event to the database.

        Args:
            db: Database session
            event_type: Type of security event
            threat_level: Threat level
            description: Human-readable description
            team_id: Team ID
            user_id: User ID
            source_ip: Source IP address
            user_agent: User agent string
            matched_patterns: List of matched patterns (for injection attempts)
            input_text: Original input text
            event_metadata: Additional metadata

        Returns:
            Created SecurityEvent instance
        """
        event = SecurityEvent(
            event_type=event_type.value,
            threat_level=threat_level.value,
            description=description,
            team_id=team_id,
            user_id=user_id,
            source_ip=source_ip,
            user_agent=user_agent,
            matched_patterns=matched_patterns,
            input_text=input_text,
            event_metadata=event_metadata or {},
        )

        db.add(event)
        await db.commit()
        await db.refresh(event)

        return event

    @classmethod
    async def get_injection_attempts_by_team(
        cls,
        db: AsyncSession,
        team_id: int,
        limit: int = 100,
    ) -> list[SecurityEvent]:
        """Get recent injection attempts for a team.

        Args:
            db: Database session
            team_id: Team ID
            limit: Maximum number of events to return

        Returns:
            List of SecurityEvent instances
        """
        from sqlalchemy import select

        stmt = (
            select(SecurityEvent)
            .where(SecurityEvent.team_id == team_id)
            .where(SecurityEvent.event_type == SecurityEventType.PROMPT_INJECTION_ATTEMPT.value)
            .order_by(SecurityEvent.created_at.desc())
            .limit(limit)
        )

        result = await db.execute(stmt)
        return list(result.scalars().all())

    @classmethod
    async def get_top_teams_with_injection_attempts(
        cls,
        db: AsyncSession,
        limit: int = 10,
    ) -> list[dict]:
        """Get teams with most injection attempts (for security dashboard).

        Args:
            db: Database session
            limit: Number of teams to return

        Returns:
            List of dicts with team_id and attempt_count
        """
        from sqlalchemy import func, select

        stmt = (
            select(
                SecurityEvent.team_id,
                func.count(SecurityEvent.id).label("attempt_count"),
            )
            .where(SecurityEvent.event_type == SecurityEventType.PROMPT_INJECTION_ATTEMPT.value)
            .where(SecurityEvent.team_id.isnot(None))
            .group_by(SecurityEvent.team_id)
            .order_by(func.count(SecurityEvent.id).desc())
            .limit(limit)
        )

        result = await db.execute(stmt)
        return [
            {"team_id": row.team_id, "attempt_count": row.attempt_count}
            for row in result
        ]
