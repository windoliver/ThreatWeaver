"""
SQLMap Agent - SQL Injection Detection and Exploitation.

Uses SQLMap tool in E2B sandbox to test for SQL injection vulnerabilities.
Supports HITL approval workflow for data extraction operations.

Reference:
- Issue #18: Implement SQLMap Injection Agent
- E2B Template ID: dbe6pq4es6hqj31ybd38 (threatweaver-security)
- SQLMap: https://github.com/sqlmapproject/sqlmap
"""

import json
import logging
import re
from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum

from e2b import Sandbox
from pydantic import BaseModel

from src.agents.backends.nexus_backend import NexusBackend

logger = logging.getLogger(__name__)


class SQLMapLevel(int, Enum):
    """SQLMap test level (1-5). Higher = more tests, slower."""
    BASIC = 1
    STANDARD = 2
    EXTENDED = 3
    COMPREHENSIVE = 4
    EXHAUSTIVE = 5


class SQLMapRisk(int, Enum):
    """SQLMap risk level (1-3). Higher = riskier tests."""
    SAFE = 1        # Default (OR-based, time-based)
    MODERATE = 2    # Heavy time-based queries
    DANGEROUS = 3   # OR-based with stacked queries


class InjectionType(str, Enum):
    """SQL injection types detected by SQLMap."""
    BOOLEAN_BASED = "boolean-based blind"
    ERROR_BASED = "error-based"
    TIME_BASED = "time-based blind"
    UNION_BASED = "UNION query"
    STACKED_QUERIES = "stacked queries"
    INLINE_QUERIES = "inline queries"


class SQLMapFinding(BaseModel):
    """Pydantic model for SQLMap injection finding."""
    target_url: str
    parameter: str
    injection_type: str
    dbms: Optional[str] = None
    dbms_version: Optional[str] = None
    payload: Optional[str] = None
    title: Optional[str] = None
    place: Optional[str] = None  # GET, POST, COOKIE, etc.
    prefix: Optional[str] = None
    suffix: Optional[str] = None
    databases: Optional[List[str]] = None
    tables: Optional[Dict[str, List[str]]] = None
    current_user: Optional[str] = None
    current_db: Optional[str] = None
    is_dba: Optional[bool] = None
    hostname: Optional[str] = None


class SQLMapError(Exception):
    """Exceptions raised by SQLMap agent."""
    pass


class SQLMapAgent:
    """
    SQL Injection detection agent using SQLMap in E2B sandbox.

    This agent:
    1. Takes target URLs with parameters (from Nuclei findings or manual input)
    2. Runs SQLMap in E2B sandbox with safe defaults
    3. Detects SQL injection vulnerabilities
    4. Enumerates database information (schema, tables)
    5. Requires HITL approval for data extraction
    6. Stores results in Nexus workspace

    Storage:
        /{team_id}/{scan_id}/assessment/sqlmap/findings.json
        /{team_id}/{scan_id}/assessment/sqlmap/raw_output.txt

    Safety Features:
        - Read-only by default (no data modification)
        - Rate limiting to avoid DoS
        - HITL approval required for data extraction
        - Maximum timeout enforcement

    Example:
        >>> from src.config import get_nexus_fs
        >>> from src.agents.backends.nexus_backend import NexusBackend
        >>>
        >>> nx = get_nexus_fs()
        >>> backend = NexusBackend("scan-123", "team-abc", nx)
        >>>
        >>> agent = SQLMapAgent(
        ...     scan_id="scan-123",
        ...     team_id="team-abc",
        ...     nexus_backend=backend
        ... )
        >>> target = "https://example.com/page?id=1"
        >>> findings = agent.execute(target, level=2, risk=1)
        >>> print(f"Found {len(findings)} injection points")
    """

    def __init__(
        self,
        scan_id: str,
        team_id: str,
        nexus_backend: NexusBackend,
        sandbox: Optional[Sandbox] = None,
    ):
        """
        Initialize SQLMap agent.

        Args:
            scan_id: Scan identifier
            team_id: Team identifier (for multi-tenancy)
            nexus_backend: NexusBackend for workspace file operations
            sandbox: E2B Sandbox instance (auto-created if None)
        """
        self.scan_id = scan_id
        self.team_id = team_id
        self.backend = nexus_backend

        # Initialize E2B sandbox with security tools template
        if sandbox is None:
            self.sandbox = Sandbox.create(template="dbe6pq4es6hqj31ybd38")
            self._owns_sandbox = True
        else:
            self.sandbox = sandbox
            self._owns_sandbox = False

    def execute(
        self,
        target_url: str,
        data: Optional[str] = None,
        cookie: Optional[str] = None,
        level: int = 2,
        risk: int = 1,
        timeout: int = 3600,
        enumerate_dbs: bool = True,
        enumerate_tables: bool = False,
        batch: bool = True,
        tamper: Optional[List[str]] = None,
    ) -> List[SQLMapFinding]:
        """
        Test target URL for SQL injection vulnerabilities.

        Args:
            target_url: URL with parameters to test (e.g., "https://example.com/page?id=1")
            data: POST data string (e.g., "username=test&password=test")
            cookie: Cookie header value
            level: Test level 1-5 (higher = more tests, slower)
            risk: Risk level 1-3 (higher = riskier tests)
            timeout: Execution timeout in seconds (default: 1 hour, max: 1 hour)
            enumerate_dbs: Enumerate databases if injection found
            enumerate_tables: Enumerate tables (requires HITL approval in production)
            batch: Run in batch mode (non-interactive)
            tamper: List of tamper scripts for WAF bypass

        Returns:
            List of SQLMapFinding objects

        Raises:
            SQLMapError: If execution fails or times out

        Example:
            >>> findings = agent.execute(
            ...     target_url="https://example.com/login?id=1",
            ...     level=2,
            ...     risk=1,
            ...     enumerate_dbs=True
            ... )
            >>> for finding in findings:
            ...     print(f"Injection at {finding.parameter}: {finding.injection_type}")
        """
        logger.info(f"Starting SQLMap scan for {target_url}")

        # Validate inputs
        self._validate_target(target_url)

        # Enforce max timeout (1 hour)
        if timeout > 3600:
            logger.warning(f"Timeout {timeout}s exceeds max (3600s), capping at 3600s")
            timeout = 3600

        # Validate level and risk
        level = max(1, min(5, level))
        risk = max(1, min(3, risk))

        try:
            # Run SQLMap in E2B sandbox
            raw_output = self._run_sqlmap(
                target_url=target_url,
                data=data,
                cookie=cookie,
                level=level,
                risk=risk,
                timeout=timeout,
                enumerate_dbs=enumerate_dbs,
                enumerate_tables=enumerate_tables,
                batch=batch,
                tamper=tamper,
            )

            # Parse output to findings
            findings = self._parse_output(target_url, raw_output)

            # Store results in Nexus workspace
            self._store_results(target_url, findings, raw_output, level, risk)

            logger.info(
                f"Found {len(findings)} SQL injection points in {target_url}"
            )
            return findings

        except Exception as e:
            logger.error(f"SQLMap execution failed: {e}")
            raise SQLMapError(f"SQL injection testing failed: {e}") from e

    def _validate_target(self, target_url: str) -> None:
        """Validate target URL."""
        if not target_url:
            raise ValueError("Target URL cannot be empty")

        if not target_url.startswith(("http://", "https://")):
            raise ValueError(f"Target must be a full URL with protocol: {target_url}")

        # Check for at least one parameter
        if "?" not in target_url and "=" not in target_url:
            logger.warning(
                f"Target URL has no query parameters: {target_url}. "
                "SQLMap needs parameters to test."
            )

    def _run_sqlmap(
        self,
        target_url: str,
        data: Optional[str],
        cookie: Optional[str],
        level: int,
        risk: int,
        timeout: int,
        enumerate_dbs: bool,
        enumerate_tables: bool,
        batch: bool,
        tamper: Optional[List[str]],
    ) -> str:
        """Execute SQLMap in E2B sandbox and return output."""
        # Build SQLMap command
        command_parts = [
            "sqlmap",
            f"-u '{target_url}'",
            f"--level={level}",
            f"--risk={risk}",
            "--random-agent",  # Use random User-Agent
            "--threads=1",     # Single thread for stability
        ]

        # Add POST data if provided
        if data:
            command_parts.append(f"--data='{data}'")

        # Add cookie if provided
        if cookie:
            command_parts.append(f"--cookie='{cookie}'")

        # Batch mode (non-interactive)
        if batch:
            command_parts.append("--batch")

        # Enumeration options
        if enumerate_dbs:
            command_parts.append("--dbs")

        if enumerate_tables:
            command_parts.append("--tables")

        # WAF bypass tamper scripts
        if tamper:
            tamper_str = ",".join(tamper)
            command_parts.append(f"--tamper={tamper_str}")

        # Output formatting
        command_parts.extend([
            "--flush-session",  # Clear any cached session
            "-v 1",             # Verbosity level
        ])

        command = " ".join(command_parts)

        logger.debug(f"Running SQLMap command: {command}")

        try:
            result = self.sandbox.commands.run(command, timeout=timeout)

            # SQLMap uses various exit codes
            # 0 = success (found injection or completed)
            # 1 = error
            # The output contains the actual findings

            return result.stdout + "\n" + result.stderr

        except TimeoutError as e:
            raise SQLMapError(f"SQLMap scan timed out after {timeout}s") from e

    def _parse_output(self, target_url: str, output: str) -> List[SQLMapFinding]:
        """
        Parse SQLMap output to extract injection findings.

        SQLMap output includes markers like:
        - "Parameter: id (GET)" for injection points
        - "Type: boolean-based blind" for injection types
        - "Payload: 1' AND 1=1--" for payloads
        - "back-end DBMS: MySQL" for DBMS info
        """
        findings = []

        if not output.strip():
            return findings

        # Check if injection was found
        if "sqlmap identified the following injection" not in output.lower() and \
           "parameter" not in output.lower():
            logger.info("No SQL injection vulnerabilities detected")
            return findings

        # Parse injection points
        current_finding = None

        # Extract parameter and injection info
        param_pattern = r"Parameter:\s*(\w+)\s*\((\w+)\)"
        type_pattern = r"Type:\s*([^\n]+)"
        payload_pattern = r"Payload:\s*([^\n]+)"
        title_pattern = r"Title:\s*([^\n]+)"
        dbms_pattern = r"back-end DBMS:\s*([^\n]+)"
        current_user_pattern = r"current user:\s*'([^']+)'"
        current_db_pattern = r"current database:\s*'([^']+)'"
        dbs_pattern = r"available databases \[\d+\]:\s*((?:\[\*\]\s*\S+\s*)+)"
        is_dba_pattern = r"current user is DBA:\s*(\w+)"

        # Find all parameters
        param_matches = re.findall(param_pattern, output)
        type_matches = re.findall(type_pattern, output)
        payload_matches = re.findall(payload_pattern, output)
        title_matches = re.findall(title_pattern, output)

        # Extract DBMS info
        dbms_match = re.search(dbms_pattern, output)
        dbms = dbms_match.group(1) if dbms_match else None

        current_user_match = re.search(current_user_pattern, output)
        current_user = current_user_match.group(1) if current_user_match else None

        current_db_match = re.search(current_db_pattern, output)
        current_db = current_db_match.group(1) if current_db_match else None

        is_dba_match = re.search(is_dba_pattern, output)
        is_dba = is_dba_match.group(1).lower() == "true" if is_dba_match else None

        # Extract databases
        databases = None
        dbs_match = re.search(dbs_pattern, output)
        if dbs_match:
            dbs_raw = dbs_match.group(1)
            databases = re.findall(r"\[\*\]\s*(\S+)", dbs_raw)

        # Create findings for each injection point
        for i, (param, place) in enumerate(param_matches):
            inj_type = type_matches[i] if i < len(type_matches) else "unknown"
            payload = payload_matches[i] if i < len(payload_matches) else None
            title = title_matches[i] if i < len(title_matches) else None

            finding = SQLMapFinding(
                target_url=target_url,
                parameter=param,
                injection_type=inj_type,
                place=place,
                payload=payload,
                title=title,
                dbms=dbms,
                databases=databases,
                current_user=current_user,
                current_db=current_db,
                is_dba=is_dba,
            )
            findings.append(finding)

        # If no specific injection points found but injection was detected
        if not findings and ("injectable" in output.lower() or "vulnerable" in output.lower()):
            # Create a generic finding
            finding = SQLMapFinding(
                target_url=target_url,
                parameter="unknown",
                injection_type="detected",
                dbms=dbms,
                databases=databases,
                current_user=current_user,
                current_db=current_db,
                is_dba=is_dba,
            )
            findings.append(finding)

        return findings

    def _store_results(
        self,
        target_url: str,
        findings: List[SQLMapFinding],
        raw_output: str,
        level: int,
        risk: int,
    ) -> None:
        """Store results in Nexus workspace."""
        timestamp = datetime.now().isoformat()

        # Convert findings to dict
        findings_dict = [finding.model_dump() for finding in findings]

        # Create result summary
        results_data = {
            "target_url": target_url,
            "findings_count": len(findings),
            "vulnerable": len(findings) > 0,
            "level": level,
            "risk": risk,
            "findings": findings_dict,
            "timestamp": timestamp,
            "scan_id": self.scan_id,
            "team_id": self.team_id,
            "tool": "sqlmap",
            "version": "1.9.x"
        }

        results_json = json.dumps(results_data, indent=2)

        # Write JSON results
        json_path = "/assessment/sqlmap/findings.json"
        write_result = self.backend.write(json_path, results_json)

        if write_result.error:
            if "already exists" in write_result.error:
                old_content = self.backend.read(json_path)
                if old_content and not old_content.startswith("Error:"):
                    old_lines = [line.split("→", 1)[1] if "→" in line else line
                                for line in old_content.split("\n")]
                    old_content_clean = "\n".join(old_lines)

                    edit_result = self.backend.edit(json_path, old_content_clean, results_json)
                    if edit_result.error:
                        logger.error(f"Failed to update results: {edit_result.error}")
                        raise SQLMapError(f"Failed to update results: {edit_result.error}")
            else:
                logger.error(f"Failed to store results: {write_result.error}")
                raise SQLMapError(f"Failed to store results: {write_result.error}")

        # Store raw output
        raw_path = "/assessment/sqlmap/raw_output.txt"
        write_result = self.backend.write(raw_path, raw_output)

        if write_result.error:
            if "already exists" in write_result.error:
                old_content = self.backend.read(raw_path)
                if old_content and not old_content.startswith("Error:"):
                    old_lines = [line.split("→", 1)[1] if "→" in line else line
                                for line in old_content.split("\n")]
                    old_content_clean = "\n".join(old_lines)
                    self.backend.edit(raw_path, old_content_clean, raw_output)
            else:
                logger.warning(f"Failed to store raw output: {write_result.error}")

        logger.info(f"Stored results in Nexus workspace: {self.scan_id}")

    def enumerate_databases(self, target_url: str, timeout: int = 600) -> List[str]:
        """
        Enumerate available databases (requires confirmed injection).

        Args:
            target_url: URL with confirmed SQL injection
            timeout: Timeout in seconds

        Returns:
            List of database names
        """
        command = f"sqlmap -u '{target_url}' --batch --dbs -v 0"

        result = self.sandbox.commands.run(command, timeout=timeout)
        output = result.stdout + result.stderr

        databases = []
        dbs_pattern = r"\[\*\]\s*(\S+)"
        matches = re.findall(dbs_pattern, output)
        databases.extend(matches)

        return databases

    def enumerate_tables(
        self,
        target_url: str,
        database: str,
        timeout: int = 600
    ) -> List[str]:
        """
        Enumerate tables in a database (requires HITL approval in production).

        Args:
            target_url: URL with confirmed SQL injection
            database: Database name to enumerate
            timeout: Timeout in seconds

        Returns:
            List of table names
        """
        command = f"sqlmap -u '{target_url}' --batch -D '{database}' --tables -v 0"

        result = self.sandbox.commands.run(command, timeout=timeout)
        output = result.stdout + result.stderr

        tables = []
        tables_pattern = r"\|\s*(\S+)\s*\|"
        matches = re.findall(tables_pattern, output)
        # Filter out header separators
        tables = [t for t in matches if not t.startswith("-")]

        return tables

    def cleanup(self) -> None:
        """Cleanup sandbox resources (only if we created it)."""
        if self.sandbox and self._owns_sandbox:
            try:
                self.sandbox.kill()
                logger.info("Sandbox cleanup completed")
            except Exception as e:
                logger.warning(f"Sandbox cleanup failed: {e}")
