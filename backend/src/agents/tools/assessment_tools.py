"""
Assessment Tools for DeepAgents.

These tools wrap our assessment agents (Nuclei, SQLMap, etc.)
so they can be used by DeepAgent sub-agents.

Each tool executes a security tool in E2B sandbox and stores results in Nexus.

Per-Thread Isolation:
- Tools extract thread_id from LangGraph's RunnableConfig
- Each thread gets its own backend/workspace: gs://bucket/{team_id}/{thread_id}/
- Results are isolated per-run automatically
"""

import json
import logging
from typing import List, Optional

from langchain_core.tools import tool
from langchain_core.runnables import RunnableConfig

from agents.assessment.nuclei_agent import NucleiAgent, SeverityLevel
from agents.assessment.sqlmap_agent import SQLMapAgent
from agents.backends.nexus_backend import NexusBackend
from config.nexus_config import get_nexus_fs

logger = logging.getLogger(__name__)


def _get_backend_from_config(config: RunnableConfig) -> tuple[str, str, NexusBackend]:
    """
    Extract thread_id from config and create backend.

    Args:
        config: RunnableConfig from LangGraph runtime

    Returns:
        Tuple of (scan_id, team_id, backend)
    """
    # Extract thread_id from LangGraph config
    configurable = config.get("configurable", {})
    thread_id = configurable.get("thread_id", "default-thread")

    # Use thread_id as scan_id for isolation
    scan_id = thread_id
    team_id = "default-team"

    # Create backend for this thread
    nexus_fs = get_nexus_fs()
    backend = NexusBackend(scan_id, team_id, nexus_fs)

    logger.info(f"🔧 Created backend for thread: {thread_id[:12]}...")
    logger.info(f"   Storage: gs://bucket/{team_id}/{scan_id}/")

    return scan_id, team_id, backend


@tool
def run_nuclei(
    targets: List[str],
    config: RunnableConfig,  # LangGraph injects this automatically
    severity_filter: Optional[List[str]] = None,
    rate_limit: int = 150,
    timeout: int = 1800,
) -> str:
    """
    Scan targets for vulnerabilities using Nuclei templates.

    This tool runs Nuclei in an isolated E2B sandbox to discover known
    vulnerabilities using community-maintained templates.

    Results are automatically stored in Nexus workspace at:
    /{team_id}/{thread_id}/assessment/nuclei/findings.json

    Args:
        targets: List of URLs to scan (e.g., ["https://example.com"])
        config: Runtime configuration (auto-injected by LangGraph)
        severity_filter: List of severities to include (default: ["critical", "high", "medium"])
        rate_limit: Requests per second (default: 150)
        timeout: Execution timeout in seconds (default: 1800, max: 1800)

    Returns:
        JSON string with vulnerability findings and metadata

    Example:
        result = run_nuclei(
            targets=["https://example.com"],
            severity_filter=["critical", "high"]
        )
        # Returns: '{"findings_count": 5, "findings": [...], "severity_counts": {...}}'
    """
    # Extract thread_id and create backend
    scan_id, team_id, backend = _get_backend_from_config(config)

    # Default severity filter
    if severity_filter is None:
        severity_filter = ["critical", "high", "medium"]

    try:
        # Create and execute Nuclei agent
        agent = NucleiAgent(
            scan_id=scan_id,
            team_id=team_id,
            nexus_backend=backend
        )

        findings = agent.execute(
            targets=targets,
            severity_filter=severity_filter,
            rate_limit=rate_limit,
            timeout=timeout,
            update_templates=True
        )

        agent.cleanup()

        # Convert findings to dict for JSON serialization
        findings_dict = [f.model_dump() for f in findings]

        # Group by severity
        severity_counts = {}
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = sum(1 for f in findings if f.severity.lower() == severity)
            if count > 0:
                severity_counts[severity] = count

        # Return structured result
        result = {
            "success": True,
            "targets_count": len(targets),
            "findings_count": len(findings),
            "severity_filter": severity_filter,
            "severity_counts": severity_counts,
            "findings": findings_dict,
            "storage_path": "/assessment/nuclei/findings.json"
        }

        logger.info(
            f"Nuclei found {len(findings)} vulnerabilities "
            f"({', '.join(str(count) for count in severity_counts.values())} by severity)"
        )
        return json.dumps(result, indent=2)

    except Exception as e:
        logger.error(f"Nuclei tool failed: {e}")
        return json.dumps({
            "success": False,
            "error": str(e),
            "targets_count": len(targets)
        })


@tool
def run_sqlmap(
    target_url: str,
    config: RunnableConfig,  # LangGraph injects this automatically
    data: Optional[str] = None,
    cookie: Optional[str] = None,
    level: int = 2,
    risk: int = 1,
    timeout: int = 3600,
    enumerate_dbs: bool = True,
) -> str:
    """
    Test a URL for SQL injection vulnerabilities using SQLMap.

    This tool runs SQLMap in an isolated E2B sandbox to detect SQL injection
    vulnerabilities and enumerate database information.

    IMPORTANT: This tool uses safe defaults (read-only operations). For data
    extraction operations, human-in-the-loop approval is required.

    Results are automatically stored in Nexus workspace at:
    /{team_id}/{thread_id}/assessment/sqlmap/findings.json

    Args:
        target_url: URL with parameters to test (e.g., "https://example.com/page?id=1")
        config: Runtime configuration (auto-injected by LangGraph)
        data: POST data string (e.g., "username=test&password=test")
        cookie: Cookie header value for authenticated testing
        level: Test level 1-5 (default: 2, higher = more thorough but slower)
        risk: Risk level 1-3 (default: 1 = safe, no destructive tests)
        timeout: Execution timeout in seconds (default: 3600, max: 3600)
        enumerate_dbs: Enumerate databases if injection is found (default: True)

    Returns:
        JSON string with SQL injection findings and database info

    Example:
        result = run_sqlmap(
            target_url="https://example.com/search?q=test",
            level=2,
            risk=1
        )
        # Returns: '{"vulnerable": true, "findings": [...], "databases": [...]}'
    """
    # Extract thread_id and create backend
    scan_id, team_id, backend = _get_backend_from_config(config)

    try:
        # Create and execute SQLMap agent
        agent = SQLMapAgent(
            scan_id=scan_id,
            team_id=team_id,
            nexus_backend=backend
        )

        findings = agent.execute(
            target_url=target_url,
            data=data,
            cookie=cookie,
            level=level,
            risk=risk,
            timeout=timeout,
            enumerate_dbs=enumerate_dbs,
            enumerate_tables=False,  # Requires HITL approval
            batch=True
        )

        agent.cleanup()

        # Convert findings to dict for JSON serialization
        findings_dict = [f.model_dump() for f in findings]

        # Extract database info
        databases = []
        dbms = None
        for finding in findings:
            if finding.databases:
                databases.extend(finding.databases)
            if finding.dbms:
                dbms = finding.dbms

        # Return structured result
        result = {
            "success": True,
            "target_url": target_url,
            "vulnerable": len(findings) > 0,
            "findings_count": len(findings),
            "dbms": dbms,
            "databases": list(set(databases)),
            "findings": findings_dict,
            "storage_path": "/assessment/sqlmap/findings.json",
            "note": "For data extraction, use request_approval tool first"
        }

        if findings:
            logger.info(
                f"SQLMap found {len(findings)} injection points "
                f"(DBMS: {dbms or 'unknown'})"
            )
        else:
            logger.info(f"SQLMap found no injection points in {target_url}")

        return json.dumps(result, indent=2)

    except Exception as e:
        logger.error(f"SQLMap tool failed: {e}")
        return json.dumps({
            "success": False,
            "error": str(e),
            "target_url": target_url,
            "vulnerable": False
        })
