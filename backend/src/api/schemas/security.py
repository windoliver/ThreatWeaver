"""Pydantic schemas for security-related structured outputs."""

from typing import Literal, Optional

from pydantic import BaseModel, Field


class VulnerabilityFinding(BaseModel):
    """Structured schema for LLM-generated vulnerability findings.

    This schema enforces structure to prevent prompt injection via free-form text.
    All fields have strict validation and max lengths to prevent abuse.
    """

    # Required fields with strict validation
    severity: Literal["critical", "high", "medium", "low", "info"] = Field(
        ...,
        description="Severity level of the vulnerability",
    )
    title: str = Field(
        ...,
        max_length=200,
        description="Brief title of the vulnerability",
    )
    description: str = Field(
        ...,
        max_length=2000,
        description="Detailed description of the vulnerability",
    )

    # Optional fields with validation
    cve_id: Optional[str] = Field(
        None,
        pattern=r"^CVE-\d{4}-\d{4,7}$",
        description="CVE identifier (e.g., CVE-2024-12345)",
    )
    cvss_score: Optional[float] = Field(
        None,
        ge=0.0,
        le=10.0,
        description="CVSS score (0.0-10.0)",
    )
    affected_resource: Optional[str] = Field(
        None,
        max_length=500,
        description="Affected resource (URL, service, etc.)",
    )

    # Evidence and remediation
    evidence: Optional[str] = Field(
        None,
        max_length=5000,
        description="Evidence of the vulnerability",
    )
    remediation: Optional[str] = Field(
        None,
        max_length=2000,
        description="Recommended remediation steps",
    )

    # Metadata
    tool_name: Optional[str] = Field(
        None,
        max_length=100,
        description="Tool that discovered the vulnerability",
    )
    references: Optional[list[str]] = Field(
        None,
        max_length=10,
        description="List of reference URLs (max 10)",
    )
    tags: Optional[list[str]] = Field(
        None,
        max_length=20,
        description="Tags for categorization (max 20)",
    )

    class Config:
        json_schema_extra = {
            "example": {
                "severity": "high",
                "title": "SQL Injection in Login Form",
                "description": "The login form is vulnerable to SQL injection via the username parameter",
                "cve_id": "CVE-2024-12345",
                "cvss_score": 8.5,
                "affected_resource": "https://example.com/login",
                "evidence": "Payload: ' OR '1'='1 resulted in authentication bypass",
                "remediation": "Use parameterized queries instead of string concatenation",
                "tool_name": "sqlmap",
                "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
                "tags": ["sql-injection", "authentication", "web"],
            }
        }


class ReconResult(BaseModel):
    """Structured schema for reconnaissance results.

    Enforces structure for subdomain enumeration, port scanning, etc.
    """

    # Required fields
    target: str = Field(
        ...,
        max_length=500,
        description="Target (domain, IP, etc.)",
    )
    tool: str = Field(
        ...,
        max_length=100,
        description="Tool used for reconnaissance",
    )
    result_type: Literal["subdomain", "port", "service", "technology", "other"] = Field(
        ...,
        description="Type of reconnaissance result",
    )

    # Result data
    value: str = Field(
        ...,
        max_length=1000,
        description="Result value (subdomain, port number, etc.)",
    )
    confidence: Optional[Literal["high", "medium", "low"]] = Field(
        None,
        description="Confidence level of the result",
    )
    metadata: Optional[dict] = Field(
        None,
        description="Additional metadata",
    )

    class Config:
        json_schema_extra = {
            "example": {
                "target": "example.com",
                "tool": "subfinder",
                "result_type": "subdomain",
                "value": "admin.example.com",
                "confidence": "high",
                "metadata": {"source": "dns"},
            }
        }


class AgentHandoff(BaseModel):
    """Structured schema for agent handoffs.

    Used for passing context between agents with strict validation.
    """

    from_agent: str = Field(
        ...,
        max_length=100,
        description="Source agent name",
    )
    to_agent: str = Field(
        ...,
        max_length=100,
        description="Destination agent name",
    )
    summary: str = Field(
        ...,
        max_length=2000,
        description="Summary of findings to pass",
    )
    key_findings: list[str] = Field(
        ...,
        max_length=50,
        description="List of key findings (max 50)",
    )
    priority: Literal["critical", "high", "medium", "low"] = Field(
        ...,
        description="Priority level for the handoff",
    )
    next_actions: list[str] = Field(
        ...,
        max_length=20,
        description="Recommended next actions (max 20)",
    )

    class Config:
        json_schema_extra = {
            "example": {
                "from_agent": "ReconCoordinator",
                "to_agent": "NucleiAgent",
                "summary": "Discovered 150 subdomains with 5 exposed admin panels",
                "key_findings": [
                    "admin.example.com - HTTP 200",
                    "dashboard.example.com - HTTP 403",
                    "api.example.com - Open API endpoint",
                ],
                "priority": "high",
                "next_actions": [
                    "Scan admin panels for vulnerabilities",
                    "Test API authentication",
                ],
            }
        }


class ToolExecutionRequest(BaseModel):
    """Structured schema for tool execution requests.

    Enforces validation for security tool execution.
    """

    tool_name: str = Field(
        ...,
        max_length=100,
        pattern=r"^[a-z0-9_-]+$",
        description="Tool name (lowercase, alphanumeric, hyphens, underscores)",
    )
    target: str = Field(
        ...,
        max_length=500,
        description="Target for the tool",
    )
    arguments: dict = Field(
        default_factory=dict,
        description="Tool-specific arguments",
    )
    requires_approval: bool = Field(
        default=False,
        description="Whether human approval is required",
    )
    justification: Optional[str] = Field(
        None,
        max_length=1000,
        description="Justification for tool execution",
    )

    class Config:
        json_schema_extra = {
            "example": {
                "tool_name": "nmap",
                "target": "192.168.1.0/24",
                "arguments": {"ports": "1-1000", "scan_type": "syn"},
                "requires_approval": False,
                "justification": "Port scan for network mapping",
            }
        }
