"""
Nuclei Agent - Template-based Vulnerability Scanning.

Uses Nuclei tool in E2B sandbox to scan targets for known vulnerabilities
using community templates. Supports severity filtering and rate limiting.

Reference:
- Issue #17: Implement Nuclei Scanning Agent
- E2B Template ID: dbe6pq4es6hqj31ybd38 (threatweaver-security)
- Nuclei: https://github.com/projectdiscovery/nuclei
"""

import json
import logging
from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum

from e2b import Sandbox
from pydantic import BaseModel

from src.agents.backends.nexus_backend import NexusBackend

logger = logging.getLogger(__name__)


class SeverityLevel(str, Enum):
    """Nuclei severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class NucleiFinding(BaseModel):
    """Pydantic model for Nuclei vulnerability finding."""
    template_id: str
    template_name: str
    severity: str
    host: str
    matched_at: str
    extracted_results: Optional[List[str]] = None
    matcher_name: Optional[str] = None
    type: Optional[str] = None
    curl_command: Optional[str] = None
    description: Optional[str] = None
    reference: Optional[List[str]] = None
    cvss_metrics: Optional[str] = None
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    tags: Optional[List[str]] = None


class NucleiError(Exception):
    """Exceptions raised by Nuclei agent."""
    pass


class NucleiAgent:
    """
    Vulnerability scanning agent using Nuclei in E2B sandbox.

    This agent:
    1. Takes target URLs (from HTTPx or other sources)
    2. Runs Nuclei in E2B sandbox with community templates
    3. Parses JSONL output to structured findings
    4. Filters by severity level
    5. Stores results in Nexus workspace

    Storage:
        /{team_id}/{scan_id}/assessment/nuclei/findings.json
        /{team_id}/{scan_id}/assessment/nuclei/raw_output.jsonl

    Example:
        >>> from src.config import get_nexus_fs
        >>> from src.agents.backends.nexus_backend import NexusBackend
        >>>
        >>> nx = get_nexus_fs()
        >>> backend = NexusBackend("scan-123", "team-abc", nx)
        >>>
        >>> agent = NucleiAgent(
        ...     scan_id="scan-123",
        ...     team_id="team-abc",
        ...     nexus_backend=backend
        ... )
        >>> targets = ["https://example.com", "https://admin.example.com"]
        >>> findings = agent.execute(targets, severity_filter=["critical", "high"])
        >>> print(f"Found {len(findings)} vulnerabilities")
    """

    def __init__(
        self,
        scan_id: str,
        team_id: str,
        nexus_backend: NexusBackend,
        sandbox: Optional[Sandbox] = None,
    ):
        """
        Initialize Nuclei agent.

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
        # Template ID: dbe6pq4es6hqj31ybd38 (threatweaver-security)
        if sandbox is None:
            self.sandbox = Sandbox.create(template="dbe6pq4es6hqj31ybd38")
            self._owns_sandbox = True
        else:
            self.sandbox = sandbox
            self._owns_sandbox = False

    def execute(
        self,
        targets: List[str],
        severity_filter: Optional[List[str]] = None,
        templates: Optional[List[str]] = None,
        rate_limit: int = 150,
        timeout: int = 1800,
        update_templates: bool = True,
    ) -> List[NucleiFinding]:
        """
        Scan targets for vulnerabilities using Nuclei templates.

        Args:
            targets: List of URLs to scan (e.g., ["https://example.com"])
            severity_filter: List of severities to include (default: ["critical", "high", "medium"])
            templates: Specific templates to use (default: None = all templates)
            rate_limit: Requests per second (default: 150)
            timeout: Execution timeout in seconds (default: 30 minutes)
            update_templates: Auto-update templates before scan (default: True)

        Returns:
            List of NucleiFinding objects

        Raises:
            NucleiError: If execution fails or times out

        Example:
            >>> findings = agent.execute(
            ...     targets=["https://example.com"],
            ...     severity_filter=["critical", "high"],
            ...     rate_limit=150
            ... )
            >>> for finding in findings:
            ...     print(f"{finding.severity}: {finding.template_name} on {finding.host}")
        """
        logger.info(f"Starting Nuclei scan for {len(targets)} targets")

        if not targets:
            logger.warning("No targets provided to Nuclei agent")
            return []

        # Default severity filter
        if severity_filter is None:
            severity_filter = ["critical", "high", "medium"]

        # Enforce max timeout (30 minutes)
        if timeout > 1800:
            logger.warning(f"Timeout {timeout}s exceeds max (1800s), capping at 1800s")
            timeout = 1800

        try:
            # Validate targets
            self._validate_targets(targets)

            # Update templates if requested
            if update_templates:
                self._update_templates()

            # Create targets file in sandbox
            targets_content = "\n".join(targets)
            self.sandbox.files.write("/tmp/nuclei_targets.txt", targets_content)

            # Run Nuclei in E2B sandbox
            jsonl_output = self._run_nuclei(
                severity_filter=severity_filter,
                templates=templates,
                rate_limit=rate_limit,
                timeout=timeout,
            )

            # Parse JSONL output to findings
            findings = self._parse_jsonl_output(jsonl_output, severity_filter)

            # Store results in Nexus workspace
            self._store_results(targets, findings, jsonl_output, severity_filter)

            logger.info(
                f"Found {len(findings)} vulnerabilities "
                f"({', '.join(severity_filter)} severity)"
            )
            return findings

        except Exception as e:
            logger.error(f"Nuclei execution failed: {e}")
            raise NucleiError(f"Vulnerability scanning failed: {e}") from e

    def _update_templates(self) -> None:
        """Update Nuclei templates to latest version."""
        logger.info("Updating Nuclei templates...")
        try:
            result = self.sandbox.commands.run(
                "nuclei -update-templates",
                timeout=120
            )
            if result.exit_code == 0:
                logger.info("Nuclei templates updated successfully")
            else:
                logger.warning(f"Template update returned non-zero exit: {result.stderr}")
        except Exception as e:
            logger.warning(f"Failed to update templates: {e}")
            # Continue with existing templates

    def _run_nuclei(
        self,
        severity_filter: List[str],
        templates: Optional[List[str]],
        rate_limit: int,
        timeout: int,
    ) -> str:
        """Execute Nuclei in E2B sandbox and return JSONL output."""
        # Build Nuclei command
        command_parts = [
            "nuclei",
            "-l /tmp/nuclei_targets.txt",
            "-jsonl",  # JSONL output for structured parsing
            "-silent",  # Suppress banner
            f"-rate-limit {rate_limit}",  # Rate limiting
            "-no-interactsh",  # Disable interactsh (external service)
        ]

        # Add severity filter
        if severity_filter:
            severity_str = ",".join(severity_filter)
            command_parts.append(f"-severity {severity_str}")

        # Add specific templates if provided
        if templates:
            template_str = ",".join(templates)
            command_parts.append(f"-templates {template_str}")

        command = " ".join(command_parts)

        logger.debug(f"Running Nuclei command: {command}")

        try:
            result = self.sandbox.commands.run(command, timeout=timeout)

            # Nuclei exits with 0 even if vulnerabilities are found
            # Non-zero typically means error
            if result.exit_code != 0:
                if "ERROR" in result.stderr or "FATAL" in result.stderr:
                    raise NucleiError(
                        f"Nuclei returned exit code {result.exit_code}: {result.stderr}"
                    )
                else:
                    logger.warning(f"Nuclei non-zero exit ({result.exit_code}): {result.stderr}")

            return result.stdout

        except TimeoutError as e:
            raise NucleiError(f"Nuclei scan timed out after {timeout}s") from e

    def _validate_targets(self, targets: List[str]) -> None:
        """Validate target list."""
        if not isinstance(targets, list):
            raise ValueError("Targets must be a list")

        if len(targets) == 0:
            raise ValueError("Targets list cannot be empty")

        for target in targets:
            if not target or not isinstance(target, str):
                raise ValueError(f"Invalid target: {target}")

            # Nuclei expects full URLs (http:// or https://)
            if not target.startswith(("http://", "https://")):
                raise ValueError(f"Target must be a full URL with protocol: {target}")

    def _parse_jsonl_output(
        self,
        jsonl_output: str,
        severity_filter: List[str]
    ) -> List[NucleiFinding]:
        """
        Parse Nuclei JSONL output into structured findings.

        Nuclei outputs one JSON object per line for each finding.
        """
        findings = []

        if not jsonl_output.strip():
            return findings

        for line in jsonl_output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)

                # Extract key fields from Nuclei output
                # Nuclei JSONL format has evolved, handle different versions
                finding = NucleiFinding(
                    template_id=data.get("template-id", "unknown"),
                    template_name=data.get("info", {}).get("name", data.get("template-id", "unknown")),
                    severity=data.get("info", {}).get("severity", "unknown"),
                    host=data.get("host", "unknown"),
                    matched_at=data.get("matched-at", data.get("matched", "")),
                    extracted_results=data.get("extracted-results"),
                    matcher_name=data.get("matcher-name"),
                    type=data.get("type"),
                    curl_command=data.get("curl-command"),
                    description=data.get("info", {}).get("description"),
                    reference=data.get("info", {}).get("reference"),
                    cvss_metrics=data.get("info", {}).get("classification", {}).get("cvss-metrics"),
                    cvss_score=data.get("info", {}).get("classification", {}).get("cvss-score"),
                    cve_id=data.get("info", {}).get("classification", {}).get("cve-id", [None])[0] if data.get("info", {}).get("classification", {}).get("cve-id") else None,
                    cwe_id=data.get("info", {}).get("classification", {}).get("cwe-id", [None])[0] if data.get("info", {}).get("classification", {}).get("cwe-id") else None,
                    tags=data.get("info", {}).get("tags")
                )

                # Filter by severity
                if finding.severity.lower() in [s.lower() for s in severity_filter]:
                    findings.append(finding)

            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse JSONL line: {e}")
                continue
            except Exception as e:
                logger.warning(f"Error processing finding: {e}")
                continue

        return findings

    def _store_results(
        self,
        targets: List[str],
        findings: List[NucleiFinding],
        raw_output: str,
        severity_filter: List[str],
    ) -> None:
        """Store results in Nexus workspace."""
        timestamp = datetime.now().isoformat()

        # Convert findings to dict for JSON serialization
        findings_dict = [finding.model_dump() for finding in findings]

        # Group findings by severity
        severity_counts = {}
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = sum(1 for f in findings if f.severity.lower() == severity)
            if count > 0:
                severity_counts[severity] = count

        # Store structured JSON results
        results_data = {
            "targets_count": len(targets),
            "targets": targets,
            "findings_count": len(findings),
            "severity_filter": severity_filter,
            "severity_counts": severity_counts,
            "findings": findings_dict,
            "timestamp": timestamp,
            "scan_id": self.scan_id,
            "team_id": self.team_id,
            "tool": "nuclei",
            "version": "3.x"
        }

        results_json = json.dumps(results_data, indent=2)

        # Write JSON results
        json_path = "/assessment/nuclei/findings.json"
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
                        raise NucleiError(f"Failed to update results: {edit_result.error}")
                else:
                    logger.error(f"Failed to read existing results")
                    raise NucleiError(f"Failed to read existing results")
            else:
                logger.error(f"Failed to store results: {write_result.error}")
                raise NucleiError(f"Failed to store results: {write_result.error}")

        # Store raw JSONL output
        jsonl_path = "/assessment/nuclei/raw_output.jsonl"
        write_result = self.backend.write(jsonl_path, raw_output)

        if write_result.error:
            if "already exists" in write_result.error:
                old_content = self.backend.read(jsonl_path)
                if old_content and not old_content.startswith("Error:"):
                    old_lines = [line.split("→", 1)[1] if "→" in line else line
                                for line in old_content.split("\n")]
                    old_content_clean = "\n".join(old_lines)

                    self.backend.edit(jsonl_path, old_content_clean, raw_output)
            else:
                logger.warning(f"Failed to store raw output: {write_result.error}")

        logger.info(f"Stored results in Nexus workspace: {self.scan_id}")

    def cleanup(self) -> None:
        """Cleanup sandbox resources (only if we created it)."""
        if self.sandbox and self._owns_sandbox:
            try:
                self.sandbox.kill()
                logger.info("Sandbox cleanup completed")
            except Exception as e:
                logger.warning(f"Sandbox cleanup failed: {e}")
