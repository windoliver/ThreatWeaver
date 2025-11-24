"""
Assessment Coordinator - LangGraph-based orchestration of assessment agents.

This module implements Issue #19: Create Assessment Supervisor (LangGraph).

The AssessmentCoordinator is a DeepAgent that orchestrates security assessment
by coordinating vulnerability scanning (Nuclei) and SQL injection testing (SQLMap).

Architecture:
- Uses LangChain's DeepAgents framework
- Spawns sub-agents via task() tool
- Makes intelligent decisions using LLM reasoning
- Implements conditional escalation (SQLi finding → SQLMap deep test)
- Stores all results in Nexus/GCS workspace
- Aggregates findings into final assessment report

Workflow:
1. Run Nuclei vulnerability scan on targets
2. Analyze findings - categorize by severity and type
3. If SQLi detected → Request HITL approval → Run SQLMap
4. Generate comprehensive assessment report

Reference:
- Issue #19: Create Assessment Supervisor (LangGraph)
- Architecture Section 3.2.4 (Assessment Supervisor)
- DeepAgents: https://github.com/langchain-ai/deepagents
"""

import json
import logging
from typing import Any, Optional, List, Dict
from datetime import datetime

from deepagents import create_deep_agent, SubAgent
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool, StructuredTool
from functools import wraps

from src.agents.backends.nexus_backend import NexusBackend
from src.agents.tools.assessment_tools import run_nuclei, run_sqlmap

logger = logging.getLogger(__name__)


def _create_bound_tools(scan_id: str, team_id: str, backend: NexusBackend):
    """
    Create assessment tools with bound context.

    This creates closures around the tools that inject the backend context
    without relying on thread-local storage (which doesn't work with LangGraph's threading).
    """
    from src.agents.context import set_agent_context

    def make_run_nuclei():
        @wraps(run_nuclei.func)
        def bound_nuclei(*args, **kwargs):
            set_agent_context(scan_id, team_id, backend)
            return run_nuclei.func(*args, **kwargs)

        return StructuredTool.from_function(
            func=bound_nuclei,
            name=run_nuclei.name,
            description=run_nuclei.description,
            args_schema=run_nuclei.args_schema
        )

    def make_run_sqlmap():
        @wraps(run_sqlmap.func)
        def bound_sqlmap(*args, **kwargs):
            set_agent_context(scan_id, team_id, backend)
            return run_sqlmap.func(*args, **kwargs)

        return StructuredTool.from_function(
            func=bound_sqlmap,
            name=run_sqlmap.name,
            description=run_sqlmap.description,
            args_schema=run_sqlmap.args_schema
        )

    return {
        'nuclei': make_run_nuclei(),
        'sqlmap': make_run_sqlmap()
    }


@tool
def request_approval(
    action: str,
    reason: str,
    risk_level: str = "high",
    targets: Optional[List[str]] = None
) -> str:
    """
    Request human-in-the-loop approval for sensitive operations.

    Use this tool before performing any exploitation or data extraction operations.
    The approval request will be logged and (in production) sent to the security team.

    Args:
        action: The action requiring approval (e.g., "SQLMap data extraction")
        reason: Why this action is needed
        risk_level: "low", "medium", "high", or "critical"
        targets: List of targets affected

    Returns:
        JSON string with approval status (for demo: auto-approved)

    Example:
        result = request_approval(
            action="Run SQLMap deep scan",
            reason="SQL injection detected in login form",
            risk_level="high",
            targets=["https://example.com/login?id=1"]
        )
    """
    # In production, this would integrate with the ApprovalRequest system
    # For MVP, we log the request and auto-approve for demo purposes
    timestamp = datetime.now().isoformat()

    approval_record = {
        "id": f"approval-{timestamp}",
        "action": action,
        "reason": reason,
        "risk_level": risk_level,
        "targets": targets or [],
        "timestamp": timestamp,
        "status": "approved",  # Auto-approve for demo
        "approved_by": "system",  # In production: human approver
        "note": "Auto-approved for demonstration. In production, requires human approval."
    }

    logger.info(f"HITL Approval Request: {action} - {reason} (auto-approved for demo)")

    return json.dumps({
        "success": True,
        "approved": True,
        "approval": approval_record,
        "message": "Operation approved. Proceed with caution."
    }, indent=2)


def create_nuclei_subagent(
    scan_id: str,
    team_id: str,
    backend: NexusBackend,
    bound_tools: Dict[str, Any],
    model: Optional[Any] = None
) -> SubAgent:
    """
    Create Nuclei sub-agent specification.

    This sub-agent specializes in vulnerability scanning using Nuclei templates.

    Args:
        scan_id: Scan identifier
        team_id: Team identifier
        backend: NexusBackend instance
        bound_tools: Dictionary of bound tools
        model: LLM model (optional)

    Returns:
        SubAgent configuration for Nuclei scanning
    """
    return SubAgent(
        name="nuclei",
        description="Vulnerability scanning specialist using Nuclei templates (CVEs, misconfigurations, exposed panels)",
        system_prompt="""You are a Vulnerability Scanning Specialist.

Your mission: Scan targets for known vulnerabilities using Nuclei templates.

**Available Tools:**
- run_nuclei: Scans targets using Nuclei vulnerability templates

**Workflow:**
1. Use run_nuclei with the target URLs
2. Analyze the findings by severity
3. Identify SQL injection vulnerabilities specifically (for escalation)
4. Report findings concisely

**Template Categories:**
- cves/: Known CVE vulnerabilities
- technologies/: Technology detection
- exposed-panels/: Admin panels, databases
- misconfiguration/: Security misconfigurations
- default-logins/: Default credentials

**Output Format:**
- Total findings count
- Breakdown by severity (critical, high, medium, low, info)
- SQL injection findings (important for escalation)
- Other notable findings

Be thorough and security-focused. Highlight anything requiring immediate attention.""",
        tools=[bound_tools['nuclei']]
    )


def create_sqlmap_subagent(
    scan_id: str,
    team_id: str,
    backend: NexusBackend,
    bound_tools: Dict[str, Any],
    model: Optional[Any] = None
) -> SubAgent:
    """
    Create SQLMap sub-agent specification.

    This sub-agent specializes in SQL injection testing.
    It should only be spawned after HITL approval.

    Args:
        scan_id: Scan identifier
        team_id: Team identifier
        backend: NexusBackend instance
        bound_tools: Dictionary of bound tools
        model: LLM model (optional)

    Returns:
        SubAgent configuration for SQL injection testing
    """
    return SubAgent(
        name="sqlmap",
        description="SQL injection testing specialist using SQLMap (requires prior approval)",
        system_prompt="""You are an SQL Injection Testing Specialist.

Your mission: Test confirmed SQL injection vulnerabilities for exploitability.

**IMPORTANT: Only run after HITL approval has been granted.**

**Available Tools:**
- run_sqlmap: Tests URLs for SQL injection vulnerabilities

**Workflow:**
1. Use run_sqlmap with the vulnerable URL
2. Use safe defaults: level=2, risk=1 (read-only)
3. Enumerate databases if injection confirmed
4. Report findings and potential impact

**Safety Rules:**
- NEVER attempt data extraction without explicit approval
- NEVER use risk level > 2 (no destructive tests)
- ALWAYS use batch mode (non-interactive)
- Report all findings to the coordinator

**Output Format:**
- Injection confirmed: Yes/No
- DBMS detected: MySQL, PostgreSQL, etc.
- Databases enumerated (names only)
- Injection type: boolean-based, time-based, etc.
- Risk assessment

Be methodical and cautious. Document everything.""",
        tools=[bound_tools['sqlmap']]
    )


def create_assessment_coordinator(
    scan_id: str,
    team_id: str,
    backend: NexusBackend,
    model: Optional[Any] = None
) -> Any:
    """
    Create Assessment Coordinator (orchestrator DeepAgent).

    This is the main coordinator agent that orchestrates security assessment
    by coordinating Nuclei (vulnerability scanning) and SQLMap (SQL injection testing).

    The coordinator implements:
    - Vulnerability discovery via Nuclei
    - Conditional escalation (SQLi → SQLMap)
    - HITL approval for exploitation
    - Risk-based prioritization
    - Comprehensive reporting

    Args:
        scan_id: Scan identifier
        team_id: Team identifier
        backend: NexusBackend instance
        model: LLM model (default: Claude Sonnet via OpenRouter)

    Returns:
        DeepAgent configured as assessment coordinator

    Example:
        >>> from config.nexus_config import get_nexus_fs
        >>> from agents.backends.nexus_backend import NexusBackend
        >>>
        >>> backend = NexusBackend("scan-123", "team-abc", get_nexus_fs())
        >>> coordinator = create_assessment_coordinator("scan-123", "team-abc", backend)
        >>> result = coordinator.invoke({
        ...     "messages": [{"role": "user", "content": "Assess https://example.com"}]
        ... })
    """
    if model is None:
        import os
        model = ChatOpenAI(
            model="anthropic/claude-sonnet-4-20250514",
            api_key=os.getenv("OPENROUTER_API_KEY"),
            base_url="https://openrouter.ai/api/v1",
            temperature=0
        )

    # Create tools with bound context
    bound_tools = _create_bound_tools(scan_id, team_id, backend)

    system_prompt = f"""You are a Security Assessment Coordinator.

Your mission: Orchestrate a comprehensive security assessment for target applications.

**Scan Context:**
- Scan ID: {scan_id}
- Team ID: {team_id}
- Workspace: /assessment/

**Available Sub-Agents:**
You can spawn specialized sub-agents using the task() tool:
- "nuclei" - Vulnerability scanning using Nuclei templates (CVEs, misconfigs, etc.)
- "sqlmap" - SQL injection testing (requires approval first)

**Available Tools:**
- request_approval: Request HITL approval for sensitive operations
- read/write: Access workspace files

**Assessment Workflow:**

1. VULNERABILITY DISCOVERY (Nuclei):
   - task(agent_type="nuclei", description="Scan {{targets}} for vulnerabilities")
   - Read results from /assessment/nuclei/findings.json
   - Categorize findings by severity and type

2. FINDING ANALYSIS:
   - Identify critical and high severity findings
   - Look for SQL injection indicators:
     * Template IDs containing "sqli" or "sql-injection"
     * CVEs related to SQL injection
     * Error-based injection patterns
   - Document all findings with context

3. CONDITIONAL ESCALATION (if SQLi detected):
   a. Request HITL approval FIRST:
      - request_approval(action="SQL injection deep testing", reason="...", targets=[...])
   b. Only after approval, spawn SQLMap:
      - task(agent_type="sqlmap", description="Test {{url}} for SQL injection")
   c. Read SQLMap results from /assessment/sqlmap/findings.json

4. RISK ASSESSMENT:
   Priority order: RCE > SQLi > Auth Bypass > XSS > Info Disclosure
   - Critical: RCE, confirmed SQLi with data access, auth bypass
   - High: Unconfirmed SQLi, sensitive data exposure
   - Medium: XSS, CSRF, information disclosure
   - Low: Version disclosure, minor misconfigurations

5. FINAL REPORT:
   Write comprehensive report to /assessment/final_report.json:
   {{
     "scan_id": "{scan_id}",
     "timestamp": "{{ISO timestamp}}",
     "targets": ["..."],
     "summary": {{
       "total_findings": N,
       "critical": N,
       "high": N,
       "medium": N,
       "low": N,
       "sqli_confirmed": true/false
     }},
     "critical_findings": [
       {{
         "title": "SQL Injection in Login",
         "severity": "critical",
         "target": "https://example.com/login",
         "details": "...",
         "remediation": "..."
       }}
     ],
     "high_findings": [...],
     "sqli_details": {{
       "vulnerable_urls": [...],
       "dbms_detected": "MySQL",
       "databases": [...],
       "exploitation_possible": true/false
     }},
     "recommendations": [
       "Implement parameterized queries",
       "Enable WAF rules for SQL injection"
     ]
   }}

**Safety Rules:**
- ALWAYS request approval before running SQLMap
- NEVER attempt data extraction without explicit approval
- Document all actions in the workspace
- Stop if targets appear out of scope

**Decision Making:**
- If >10 critical findings: Focus on most exploitable first
- If SQLi detected: Always escalate (with approval)
- If WAF detected: Note evasion may be needed
- If rate-limited: Reduce scan intensity

Be thorough, methodical, and security-focused. Your assessment helps protect systems."""

    # Create sub-agents
    sub_agents = [
        create_nuclei_subagent(scan_id, team_id, backend, bound_tools),
        create_sqlmap_subagent(scan_id, team_id, backend, bound_tools)
    ]

    # Coordinator has access to request_approval tool directly
    # plus the backend read/write capabilities from create_deep_agent
    return create_deep_agent(
        model=model,
        backend=backend,
        system_prompt=system_prompt,
        tools=[request_approval],
        subagents=sub_agents
    )


def create_quick_assessment(
    targets: List[str],
    scan_id: str,
    team_id: str,
    backend: NexusBackend,
    model: Optional[Any] = None,
    severity_filter: List[str] = None
) -> Dict[str, Any]:
    """
    Run a quick automated assessment without LLM coordination.

    This is a simpler, faster assessment that runs Nuclei directly
    and conditionally triggers SQLMap if SQL injection is found.

    Useful for CI/CD pipelines or automated scanning.

    Args:
        targets: List of URLs to assess
        scan_id: Scan identifier
        team_id: Team identifier
        backend: NexusBackend instance
        model: LLM model (not used in quick mode)
        severity_filter: Severity levels to scan (default: critical, high, medium)

    Returns:
        Dictionary with assessment results

    Example:
        >>> result = create_quick_assessment(
        ...     targets=["https://example.com"],
        ...     scan_id="quick-123",
        ...     team_id="team-abc",
        ...     backend=backend
        ... )
        >>> print(f"Found {result['summary']['total_findings']} vulnerabilities")
    """
    from src.agents.assessment.nuclei_agent import NucleiAgent
    from src.agents.assessment.sqlmap_agent import SQLMapAgent

    if severity_filter is None:
        severity_filter = ["critical", "high", "medium"]

    timestamp = datetime.now().isoformat()

    # Phase 1: Nuclei scan
    logger.info(f"Starting quick assessment for {len(targets)} targets")

    nuclei_agent = NucleiAgent(
        scan_id=scan_id,
        team_id=team_id,
        nexus_backend=backend
    )

    nuclei_findings = nuclei_agent.execute(
        targets=targets,
        severity_filter=severity_filter,
        rate_limit=150,
        timeout=600
    )

    nuclei_agent.cleanup()

    # Categorize findings
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    sqli_findings = []

    for finding in nuclei_findings:
        sev = finding.severity.lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Check for SQL injection indicators
        template_id = finding.template_id.lower() if finding.template_id else ""
        name = finding.name.lower() if finding.name else ""

        if "sqli" in template_id or "sql" in template_id or "injection" in name:
            sqli_findings.append(finding)

    # Phase 2: SQLMap (if SQLi detected)
    sqlmap_results = None
    if sqli_findings:
        logger.info(f"SQL injection indicators found: {len(sqli_findings)}, running SQLMap")

        sqlmap_agent = SQLMapAgent(
            scan_id=scan_id,
            team_id=team_id,
            nexus_backend=backend
        )

        for sqli in sqli_findings[:3]:  # Test top 3 potential SQLi URLs
            try:
                findings = sqlmap_agent.execute(
                    target_url=sqli.matched_at or sqli.host,
                    level=2,
                    risk=1,
                    timeout=300
                )
                if findings:
                    sqlmap_results = {
                        "vulnerable": True,
                        "findings": [f.model_dump() for f in findings]
                    }
                    break
            except Exception as e:
                logger.warning(f"SQLMap scan failed for {sqli.host}: {e}")

        sqlmap_agent.cleanup()

    # Build result
    result = {
        "scan_id": scan_id,
        "team_id": team_id,
        "timestamp": timestamp,
        "targets": targets,
        "summary": {
            "total_findings": len(nuclei_findings),
            **severity_counts,
            "sqli_indicators": len(sqli_findings),
            "sqli_confirmed": sqlmap_results is not None and sqlmap_results.get("vulnerable", False)
        },
        "nuclei_findings": [f.model_dump() for f in nuclei_findings],
        "sqli_details": sqlmap_results,
        "status": "completed"
    }

    # Store final report
    report_json = json.dumps(result, indent=2)
    backend.write("/assessment/quick_report.json", report_json)

    logger.info(f"Quick assessment completed: {len(nuclei_findings)} findings")

    return result
