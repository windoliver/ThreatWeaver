"""Pydantic schemas for approval requests."""

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field

from src.db.models.approval import ApprovalRequestType, ApprovalStatus


# Request schemas


class ApprovalRequestCreate(BaseModel):
    """Schema for creating an approval request."""

    scan_id: int = Field(..., description="ID of the scan requesting approval")
    request_type: ApprovalRequestType = Field(
        ..., description="Type of approval request"
    )
    title: str = Field(..., max_length=500, description="Short title for the request")
    description: str = Field(..., description="Detailed description of what needs approval")
    risk_level: str = Field(..., description="Risk level (LOW, MEDIUM, HIGH, CRITICAL)")
    context: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional context (target, vulnerability details, etc.)",
    )
    requested_action: Dict[str, Any] = Field(
        ..., description="The action being requested (tool, parameters, etc.)"
    )
    expiry_hours: int = Field(
        default=1,
        ge=1,
        le=24,
        description="Hours until auto-expiry (default: 1)",
    )

    class Config:
        json_schema_extra = {
            "example": {
                "scan_id": 123,
                "request_type": "exploit_attempt",
                "title": "SQLMap data extraction for /api/login",
                "description": "Execute SQLMap to extract user table from database",
                "risk_level": "HIGH",
                "context": {
                    "target": "https://api.example.com/login",
                    "vulnerability": "SQL Injection",
                    "cvss_score": 8.5,
                },
                "requested_action": {
                    "tool": "sqlmap",
                    "parameters": ["--dump", "-T", "users"],
                },
                "expiry_hours": 1,
            }
        }


class ApprovalReview(BaseModel):
    """Schema for reviewing an approval request."""

    approve: bool = Field(..., description="True to approve, False to reject")
    rejection_reason: Optional[str] = Field(
        None, description="Reason for rejection (required if approve=False)"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "approve": True,
                "rejection_reason": None,
            }
        }


# Response schemas


class ApprovalRequestResponse(BaseModel):
    """Schema for approval request response."""

    id: int
    scan_id: int
    request_type: str
    status: str
    title: str
    description: str
    risk_level: str
    context: Dict[str, Any]
    requested_action: Dict[str, Any]
    approved_by: Optional[int]
    approved_at: Optional[datetime]
    rejection_reason: Optional[str]
    expires_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime

    # Computed fields
    is_expired: bool = Field(
        default=False, description="True if request has expired"
    )
    time_remaining_minutes: Optional[int] = Field(
        None, description="Minutes remaining until expiry"
    )

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": 456,
                "scan_id": 123,
                "request_type": "exploit_attempt",
                "status": "pending",
                "title": "SQLMap data extraction for /api/login",
                "description": "Execute SQLMap to extract user table from database",
                "risk_level": "HIGH",
                "context": {
                    "target": "https://api.example.com/login",
                    "vulnerability": "SQL Injection",
                    "cvss_score": 8.5,
                },
                "requested_action": {
                    "tool": "sqlmap",
                    "parameters": ["--dump", "-T", "users"],
                },
                "approved_by": None,
                "approved_at": None,
                "rejection_reason": None,
                "expires_at": "2025-11-19T23:59:00Z",
                "created_at": "2025-11-19T22:59:00Z",
                "updated_at": "2025-11-19T22:59:00Z",
                "is_expired": False,
                "time_remaining_minutes": 55,
            }
        }


class ApprovalRequestList(BaseModel):
    """Schema for list of approval requests."""

    approvals: list[ApprovalRequestResponse]
    total: int

    class Config:
        json_schema_extra = {
            "example": {
                "approvals": [
                    {
                        "id": 456,
                        "scan_id": 123,
                        "request_type": "exploit_attempt",
                        "status": "pending",
                        "title": "SQLMap data extraction",
                        "description": "Execute SQLMap...",
                        "risk_level": "HIGH",
                        "context": {},
                        "requested_action": {},
                        "approved_by": None,
                        "approved_at": None,
                        "rejection_reason": None,
                        "expires_at": "2025-11-19T23:59:00Z",
                        "created_at": "2025-11-19T22:59:00Z",
                        "updated_at": "2025-11-19T22:59:00Z",
                        "is_expired": False,
                        "time_remaining_minutes": 55,
                    }
                ],
                "total": 1,
            }
        }


# Helper functions to enrich responses


def enrich_approval_response(approval) -> dict:
    """
    Enrich approval response with computed fields.

    Args:
        approval: ApprovalRequest model instance

    Returns:
        Dict with additional computed fields
    """
    from src.services.approval import ApprovalService

    data = {
        "id": approval.id,
        "scan_id": approval.scan_id,
        "request_type": approval.request_type,
        "status": approval.status,
        "title": approval.title,
        "description": approval.description,
        "risk_level": approval.risk_level,
        "context": approval.context,
        "requested_action": approval.requested_action,
        "approved_by": approval.approved_by,
        "approved_at": approval.approved_at,
        "rejection_reason": approval.rejection_reason,
        "expires_at": approval.expires_at,
        "created_at": approval.created_at,
        "updated_at": approval.updated_at,
    }

    # Add computed fields
    data["is_expired"] = ApprovalService.is_expired(approval)

    # Calculate time remaining
    if approval.expires_at and approval.status == ApprovalStatus.PENDING.value:
        time_remaining = approval.expires_at - datetime.utcnow()
        data["time_remaining_minutes"] = max(0, int(time_remaining.total_seconds() / 60))
    else:
        data["time_remaining_minutes"] = None

    return data
