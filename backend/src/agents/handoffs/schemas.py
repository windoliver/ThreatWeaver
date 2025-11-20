"""
TypedDict schemas for hybrid handoffs.

These schemas define the structure of handoff data passed between agents.
They ensure type safety and serve as contracts between workflow stages.

Architecture:
- ReconHandoff: Data passed from ReconEngine → AssessmentEngine
- AssessmentHandoff: Data passed from AssessmentEngine → ExploitEngine
- ScanState: Complete LangGraph workflow state (in-memory)
"""

from datetime import datetime
from typing import List, Optional, TypedDict


class ReconHandoff(TypedDict, total=False):
    """
    Ephemeral handoff data from ReconEngine.

    Lifecycle: Created during scan, stored in LangGraph state (in-memory),
               persisted to Nexus at scan end for historical context.

    Fields:
        subdomains: Discovered subdomains (e.g., ["api.target.com", "admin.target.com"])
        live_hosts: Live HTTP/HTTPS endpoints with metadata
        high_value_targets: LLM-prioritized targets (e.g., admin panels, APIs)
        open_ports: Port scan results (e.g., [{"host": "1.2.3.4", "port": 443, "service": "https"}])
        technologies: Detected tech stack (e.g., ["nginx", "php", "wordpress"])
        metadata: Scan metadata (timestamp, tool versions, etc.)
    """

    subdomains: List[str]
    live_hosts: List[dict]  # [{"url": "https://...", "status_code": 200, ...}]
    high_value_targets: List[str]  # LLM-prioritized
    open_ports: List[dict]  # [{"host": "1.2.3.4", "port": 443, "service": "https"}]
    technologies: List[str]  # ["nginx", "wordpress", "php"]
    metadata: dict  # {"timestamp": "...", "tool_versions": {...}}


class AssessmentHandoff(TypedDict, total=False):
    """
    Ephemeral handoff data from AssessmentEngine.

    Lifecycle: Created during scan, stored in LangGraph state (in-memory),
               persisted to Nexus at scan end for historical context.

    Fields:
        vulnerabilities: Discovered vulnerabilities (Nuclei, custom scanners)
        critical_findings: High-severity issues requiring immediate attention
        suggested_exploits: LLM-recommended exploitation strategies
        attack_surface_score: Numerical score (0-100) of attack surface size
        metadata: Scan metadata (timestamp, tool versions, etc.)
    """

    vulnerabilities: List[dict]  # [{"template": "cve-2023-1234", "severity": "critical", ...}]
    critical_findings: List[str]  # ["SQL injection in /api/login", "RCE via file upload"]
    suggested_exploits: List[str]  # ["Use SQLMap for /api/login", "Test file upload bypass"]
    attack_surface_score: int  # 0-100
    metadata: dict


class ScanState(TypedDict, total=False):
    """
    Complete LangGraph workflow state (in-memory).

    This is the primary state object passed through the LangGraph workflow.
    It contains both ephemeral (current scan) and historical (previous scan) data.

    Lifecycle: Created at scan start, updated by nodes, persisted at scan end.

    Fields:
        # Scan identification
        scan_id: Unique scan identifier (e.g., "scan-20251119-123456")
        team_id: Team identifier for multi-tenancy
        target: Scan target (domain, IP, CIDR)

        # Active scan handoffs (ephemeral, in-memory only)
        recon_handoff: Current scan's recon results
        assessment_handoff: Current scan's assessment results

        # Historical context (loaded from Nexus)
        previous_recon: Previous scan's recon results (for diff detection)
        previous_assessment: Previous scan's assessment results

        # Diff analysis (computed from current vs. previous)
        new_subdomains: Newly discovered subdomains
        removed_subdomains: Subdomains that disappeared
        new_vulnerabilities: Newly discovered vulnerabilities
        fixed_vulnerabilities: Vulnerabilities that were fixed

        # Workflow control
        next_step: Next workflow stage ("deep_osint", "vuln_scan", "exploit", etc.)
        metadata: Workflow metadata (start time, user preferences, etc.)
    """

    # Scan identification
    scan_id: str
    team_id: str
    target: str

    # Active scan handoffs (ephemeral, in-memory)
    recon_handoff: Optional[ReconHandoff]
    assessment_handoff: Optional[AssessmentHandoff]

    # Historical context (loaded from Nexus)
    previous_recon: Optional[ReconHandoff]
    previous_assessment: Optional[AssessmentHandoff]

    # Diff analysis
    new_subdomains: List[str]
    removed_subdomains: List[str]
    new_vulnerabilities: List[dict]
    fixed_vulnerabilities: List[dict]

    # Workflow control
    next_step: str  # "deep_osint", "vuln_scan", "exploit", "report"
    metadata: dict
