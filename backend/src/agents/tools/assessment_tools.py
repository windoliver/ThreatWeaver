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

from src.agents.assessment.nuclei_agent import NucleiAgent, SeverityLevel
from src.agents.assessment.sqlmap_agent import SQLMapAgent
from src.agents.assessment.xsstrike_agent import XSStrikeAgent
from src.agents.assessment.testssl_agent import TestsslAgent
from src.agents.backends.nexus_backend import NexusBackend
from src.config.nexus_config import get_nexus_fs

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


@tool
def run_xsstrike(
    target_url: str,
    config: RunnableConfig,  # LangGraph injects this automatically
    data: Optional[str] = None,
    crawl: bool = False,
    skip_dom: bool = False,
    timeout: int = 600,
) -> str:
    """
    Test a URL for Cross-Site Scripting (XSS) vulnerabilities using XSStrike.

    This tool runs XSStrike in an isolated E2B sandbox to detect XSS vulnerabilities
    using intelligent payload generation and WAF bypass techniques.

    XSStrike can detect:
    - Reflected XSS
    - DOM-based XSS
    - Blind XSS (with external service)

    Results are automatically stored in Nexus workspace at:
    /{team_id}/{thread_id}/assessment/xsstrike/findings.json

    Args:
        target_url: URL with parameters to test (e.g., "https://example.com/search?q=test")
        config: Runtime configuration (auto-injected by LangGraph)
        data: POST data string (e.g., "name=test&comment=hello")
        crawl: Enable crawling to find more injection points (default: False)
        skip_dom: Skip DOM-based XSS testing for speed (default: False)
        timeout: Execution timeout in seconds (default: 600)

    Returns:
        JSON string with XSS findings and metadata

    Example:
        result = run_xsstrike(
            target_url="https://example.com/search?q=test"
        )
        # Returns: '{"vulnerable_count": 1, "findings": [{"parameter": "q", "xss_type": "reflected"}]}'
    """
    # Extract thread_id and create backend
    scan_id, team_id, backend = _get_backend_from_config(config)

    try:
        # Create and execute XSStrike agent
        agent = XSStrikeAgent(
            scan_id=scan_id,
            team_id=team_id,
            nexus_backend=backend
        )

        findings = agent.execute(
            target_url=target_url,
            data=data,
            crawl=crawl,
            skip_dom=skip_dom,
            timeout=timeout
        )

        agent.cleanup()

        # Summarize findings
        vuln_findings = [f for f in findings if f.vulnerable]
        xss_types = {}
        for f in vuln_findings:
            if f.xss_type:
                xss_types[f.xss_type] = xss_types.get(f.xss_type, 0) + 1

        # Return structured result
        result = {
            "success": True,
            "target_url": target_url,
            "vulnerable": len(vuln_findings) > 0,
            "vulnerable_count": len(vuln_findings),
            "xss_types": xss_types,
            "findings": [f.model_dump() for f in findings],
            "storage_path": "/assessment/xsstrike/findings.json"
        }

        if vuln_findings:
            logger.info(
                f"XSStrike found {len(vuln_findings)} XSS vulnerabilities "
                f"({', '.join(f'{k}: {v}' for k, v in xss_types.items())})"
            )
        else:
            logger.info(f"XSStrike found no XSS vulnerabilities in {target_url}")

        return json.dumps(result, indent=2)

    except Exception as e:
        logger.error(f"XSStrike tool failed: {e}")
        return json.dumps({
            "success": False,
            "error": str(e),
            "target_url": target_url,
            "vulnerable": False
        })


@tool
def run_testssl(
    target: str,
    config: RunnableConfig,  # LangGraph injects this automatically
    port: int = 443,
    check_vulnerabilities: bool = True,
    timeout: int = 600,
) -> str:
    """
    Test TLS/SSL security configuration using testssl.sh.

    This tool runs testssl.sh in an isolated E2B sandbox to analyze TLS/SSL
    security including protocols, ciphers, certificates, and known vulnerabilities.

    Tests include:
    - Protocol versions (SSLv2, SSLv3, TLS 1.0-1.3)
    - Cipher suite strength and security
    - Certificate validation and expiry
    - Known vulnerabilities: Heartbleed, POODLE, ROBOT, DROWN, etc.

    Results are automatically stored in Nexus workspace at:
    /{team_id}/{thread_id}/assessment/testssl/findings.json

    Args:
        target: Target hostname or URL (e.g., "example.com" or "https://example.com")
        config: Runtime configuration (auto-injected by LangGraph)
        port: Port to test (default: 443)
        check_vulnerabilities: Test for known TLS/SSL vulnerabilities (default: True)
        timeout: Execution timeout in seconds (default: 600)

    Returns:
        JSON string with TLS/SSL findings and security rating

    Example:
        result = run_testssl(target="example.com")
        # Returns: '{"overall_rating": "A", "vulnerabilities": [], "protocols": {...}}'
    """
    # Extract thread_id and create backend
    scan_id, team_id, backend = _get_backend_from_config(config)

    try:
        # Create and execute testssl agent
        agent = TestsslAgent(
            scan_id=scan_id,
            team_id=team_id,
            nexus_backend=backend
        )

        finding = agent.execute(
            target=target,
            port=port,
            check_vulnerabilities=check_vulnerabilities,
            timeout=timeout
        )

        agent.cleanup()

        # Summarize vulnerabilities
        vuln_counts = {}
        for v in finding.vulnerabilities:
            vuln_counts[v.severity] = vuln_counts.get(v.severity, 0) + 1

        # Return structured result
        result = {
            "success": True,
            "target": finding.target,
            "overall_rating": finding.overall_rating,
            "protocols": finding.protocols,
            "vulnerability_count": len(finding.vulnerabilities),
            "vulnerability_summary": vuln_counts,
            "vulnerabilities": [v.model_dump() for v in finding.vulnerabilities],
            "certificate": finding.certificate.model_dump() if finding.certificate else None,
            "storage_path": "/assessment/testssl/findings.json"
        }

        high_vulns = sum(1 for v in finding.vulnerabilities if v.severity in ["critical", "high"])
        logger.info(
            f"testssl completed for {target}: Rating {finding.overall_rating}, "
            f"{high_vulns} high+ vulnerabilities"
        )

        return json.dumps(result, indent=2)

    except Exception as e:
        logger.error(f"testssl tool failed: {e}")
        return json.dumps({
            "success": False,
            "error": str(e),
            "target": target
        })
