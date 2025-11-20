"""Security endpoints for prompt injection detection and security dashboard."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ...db.session import get_db
from ...security import PromptGuard, SecurityError
from ...security.dependencies import CurrentActiveUser, get_current_team

router = APIRouter(prefix="/security", tags=["Security"])


class ValidateInputRequest(BaseModel):
    """Request model for input validation."""

    text: str


class ValidateInputResponse(BaseModel):
    """Response model for input validation."""

    safe: bool
    threat_level: str
    matched_patterns: list[dict] | None = None
    message: str


class SecurityDashboardResponse(BaseModel):
    """Response model for security dashboard."""

    team_injection_attempts: list[dict]
    recent_events: list[dict]


@router.post("/validate-input", response_model=ValidateInputResponse)
async def validate_input(
    request: ValidateInputRequest,
    http_request: Request,
    current_user: CurrentActiveUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ValidateInputResponse:
    """Validate user input for prompt injection attempts.

    This endpoint demonstrates the PromptGuard in action by analyzing
    user input and detecting potential injection attempts.

    Args:
        request: Input validation request
        http_request: HTTP request object for IP/user agent
        current_user: Authenticated user
        db: Database session

    Returns:
        Validation result with threat level and matched patterns
    """
    # Analyze input
    threat_level, matched_patterns = PromptGuard.analyze(request.text)

    # Get request metadata
    source_ip = http_request.client.host if http_request.client else None
    user_agent = http_request.headers.get("user-agent")

    try:
        # Validate (will raise SecurityError if dangerous)
        await PromptGuard.validate_user_input(
            text=request.text,
            db=db,
            user_id=current_user.id,
            source_ip=source_ip,
            user_agent=user_agent,
        )

        # Input is safe (no dangerous patterns)
        return ValidateInputResponse(
            safe=True,
            threat_level=threat_level.value,
            matched_patterns=matched_patterns if matched_patterns else None,
            message="Input is safe" if not matched_patterns else "Warning patterns detected but not blocked",
        )

    except SecurityError as e:
        # Dangerous patterns detected
        return ValidateInputResponse(
            safe=False,
            threat_level=threat_level.value,
            matched_patterns=matched_patterns,
            message=str(e),
        )


@router.get("/dashboard", response_model=SecurityDashboardResponse)
async def security_dashboard(
    current_user: CurrentActiveUser,
    current_team: Annotated[int, Depends(get_current_team)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> SecurityDashboardResponse:
    """Get security dashboard data for the current team.

    Shows recent injection attempts and top teams with attempts.

    Args:
        current_user: Authenticated user
        current_team: Current team ID
        db: Database session

    Returns:
        Security dashboard data
    """
    # Get recent injection attempts for this team
    recent_events = await PromptGuard.get_injection_attempts_by_team(
        db=db,
        team_id=current_team,
        limit=10,
    )

    # Only superusers can see top teams data
    team_attempts = []
    if current_user.is_superuser:
        team_attempts = await PromptGuard.get_top_teams_with_injection_attempts(
            db=db,
            limit=10,
        )

    return SecurityDashboardResponse(
        team_injection_attempts=team_attempts,
        recent_events=[
            {
                "id": event.id,
                "threat_level": event.threat_level,
                "description": event.description,
                "matched_patterns": event.matched_patterns,
                "created_at": event.created_at.isoformat(),
                "user_id": event.user_id,
            }
            for event in recent_events
        ],
    )
