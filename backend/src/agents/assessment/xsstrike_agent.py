"""
XSStrike Agent - XSS Vulnerability Detection.

Uses XSStrike tool in E2B sandbox to detect Cross-Site Scripting (XSS)
vulnerabilities in web applications. XSStrike is an advanced XSS detection
suite with intelligent payloads and WAF bypass techniques.

Reference:
- Issue #32: Implement XSStrike XSS Detection Agent
- E2B Template ID: dbe6pq4es6hqj31ybd38 (threatweaver-security)
- XSStrike: https://github.com/s0md3v/XSStrike
"""

import json
import logging
import re
from datetime import datetime, timezone
from typing import List, Optional
from enum import Enum

from pydantic import BaseModel
from e2b import Sandbox

from src.agents.backends.nexus_backend import NexusBackend

logger = logging.getLogger(__name__)


class XSSType(str, Enum):
    """XSS vulnerability types."""
    REFLECTED = "reflected"
    STORED = "stored"
    DOM = "dom"
    BLIND = "blind"


class XSSStrikeError(Exception):
    """Exceptions raised by XSStrike agent."""
    pass


class XSSFinding(BaseModel):
    """Represents an XSS vulnerability finding from XSStrike."""
    target_url: str                         # URL that was tested
    vulnerable: bool                        # Whether XSS was found
    xss_type: Optional[str] = None          # Type of XSS (reflected, dom, etc.)
    parameter: Optional[str] = None         # Vulnerable parameter name
    payload: Optional[str] = None           # Successful XSS payload
    confidence: str = "unknown"             # high, medium, low
    waf_detected: Optional[str] = None      # WAF/filter detected
    bypass_used: Optional[str] = None       # WAF bypass technique if any
    context: Optional[str] = None           # HTML context (attribute, script, etc.)
    raw_output: Optional[str] = None        # Raw XSStrike output


class XSStrikeAgent:
    """
    XSS detection agent using XSStrike in E2B sandbox.

    This agent:
    1. Runs XSStrike in E2B sandbox (isolated, secure execution)
    2. Tests URLs for reflected, DOM-based, and blind XSS
    3. Uses intelligent payload generation and WAF bypass
    4. Stores findings in Nexus workspace

    Storage:
        /{team_id}/{scan_id}/assessment/xsstrike/findings.json
        /{team_id}/{scan_id}/assessment/xsstrike/raw_output.txt

    Example:
        >>> from src.config import get_nexus_fs
        >>> from src.agents.backends.nexus_backend import NexusBackend
        >>>
        >>> nx = get_nexus_fs()
        >>> backend = NexusBackend("scan-123", "team-abc", nx)
        >>>
        >>> agent = XSStrikeAgent(
        ...     scan_id="scan-123",
        ...     team_id="team-abc",
        ...     nexus_backend=backend
        ... )
        >>> findings = agent.execute("https://example.com/search?q=test")
        >>> for f in findings:
        ...     if f.vulnerable:
        ...         print(f"XSS found in {f.parameter}: {f.payload}")
    """

    def __init__(
        self,
        scan_id: str,
        team_id: str,
        nexus_backend: NexusBackend,
        sandbox: Optional[Sandbox] = None,
    ):
        """
        Initialize XSStrike agent.

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
            self.sandbox = Sandbox.create(template="dbe6pq4es6hqj31ybd38", timeout=1800)
            self._owns_sandbox = True
        else:
            self.sandbox = sandbox
            self._owns_sandbox = False

    def execute(
        self,
        target_url: str,
        data: Optional[str] = None,
        headers: Optional[dict] = None,
        crawl: bool = False,
        blind_xss: bool = False,
        skip_dom: bool = False,
        timeout: int = 600,
    ) -> List[XSSFinding]:
        """
        Test a URL for XSS vulnerabilities.

        Args:
            target_url: URL with parameters to test (e.g., "https://example.com/search?q=test")
            data: POST data string (e.g., "name=test&comment=hello")
            headers: Custom headers dict (e.g., {"Cookie": "session=xyz"})
            crawl: Enable crawling to find more injection points (default: False)
            blind_xss: Test for blind XSS (default: False)
            skip_dom: Skip DOM-based XSS testing (default: False)
            timeout: Execution timeout in seconds (default: 600)

        Returns:
            List of XSSFinding objects for vulnerabilities found

        Raises:
            XSSStrikeError: If execution fails or times out

        Example:
            >>> findings = agent.execute(
            ...     "https://example.com/search?q=test",
            ...     headers={"Cookie": "session=abc"}
            ... )
            >>> for f in findings:
            ...     print(f"{f.parameter}: {f.xss_type} XSS")
        """
        logger.info(f"Starting XSS detection for {target_url}")

        try:
            # Validate URL
            self._validate_url(target_url)

            # Run XSStrike in E2B sandbox
            raw_output = self._run_xsstrike(
                target_url=target_url,
                data=data,
                headers=headers,
                crawl=crawl,
                blind_xss=blind_xss,
                skip_dom=skip_dom,
                timeout=timeout,
            )

            # Parse output
            findings = self._parse_output(raw_output, target_url)

            # Store results in Nexus workspace
            self._store_results(target_url, findings, raw_output)

            vuln_count = sum(1 for f in findings if f.vulnerable)
            logger.info(f"XSStrike found {vuln_count} XSS vulnerabilities in {target_url}")
            return findings

        except Exception as e:
            logger.error(f"XSStrike execution failed: {e}")
            raise XSSStrikeError(f"XSS detection failed: {e}") from e

    def _run_xsstrike(
        self,
        target_url: str,
        data: Optional[str],
        headers: Optional[dict],
        crawl: bool,
        blind_xss: bool,
        skip_dom: bool,
        timeout: int,
    ) -> str:
        """Execute XSStrike in E2B sandbox."""
        # Build XSStrike command
        cmd_parts = [
            "python3",
            "/opt/XSStrike/xsstrike.py",
            f"-u '{target_url}'",
            "--skip",  # Skip confirmation prompts
        ]

        # Add POST data if provided
        if data:
            cmd_parts.append(f"-d '{data}'")

        # Add headers
        if headers:
            for key, value in headers.items():
                cmd_parts.append(f"--headers '{key}: {value}'")

        # Add crawling
        if crawl:
            cmd_parts.append("--crawl")

        # Add blind XSS
        if blind_xss:
            cmd_parts.append("--blind")

        # Skip DOM testing if requested
        if skip_dom:
            cmd_parts.append("--skip-dom")

        command = " ".join(cmd_parts)
        logger.info(f"Running XSStrike: {command[:100]}...")

        try:
            # First check if XSStrike is installed, if not install it
            check_result = self.sandbox.commands.run("test -d /opt/XSStrike", timeout=30)
            if check_result.exit_code != 0:
                logger.info("Installing XSStrike in sandbox...")
                install_cmds = [
                    "git clone https://github.com/s0md3v/XSStrike.git /opt/XSStrike",
                    "pip install -r /opt/XSStrike/requirements.txt",
                ]
                for cmd in install_cmds:
                    install_result = self.sandbox.commands.run(cmd, timeout=120)
                    if install_result.exit_code != 0:
                        logger.warning(f"Install command failed: {cmd}")

            result = self.sandbox.commands.run(
                command,
                timeout=timeout,
            )

            output = result.stdout + "\n" + result.stderr
            return output

        except TimeoutError as e:
            raise XSSStrikeError(f"XSStrike timed out after {timeout}s") from e

    def _validate_url(self, url: str) -> None:
        """Validate URL format."""
        if not url.startswith(('http://', 'https://')):
            raise ValueError(f"URL must start with http:// or https://: {url}")

        # Basic URL validation
        pattern = r'^https?://[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9](:[0-9]+)?(/.*)?$'
        if not re.match(pattern, url):
            raise ValueError(f"Invalid URL format: {url}")

    def _parse_output(self, raw_output: str, target_url: str) -> List[XSSFinding]:
        """Parse XSStrike output into XSSFinding objects."""
        findings = []

        # XSStrike output patterns
        # Example: "[+] Vulnerable: param=value"
        # Example: "Payload: <script>alert(1)</script>"
        # Example: "Context: attribute"
        # Example: "WAF: Cloudflare detected"

        lines = raw_output.strip().split('\n')
        current_finding = None

        for line in lines:
            line = line.strip()
            if not line:
                continue

            line_lower = line.lower()

            # Check for vulnerability detection
            if "vulnerable" in line_lower or "[+]" in line:
                # Extract parameter if possible
                param_match = re.search(r'parameter[:\s]+(\w+)', line, re.IGNORECASE)
                param = param_match.group(1) if param_match else None

                current_finding = XSSFinding(
                    target_url=target_url,
                    vulnerable=True,
                    parameter=param,
                    confidence="high",
                )
                findings.append(current_finding)

            # Extract payload
            elif current_finding and "payload" in line_lower:
                payload_match = re.search(r'payload[:\s]+(.+)', line, re.IGNORECASE)
                if payload_match:
                    current_finding.payload = payload_match.group(1).strip()

            # Extract context
            elif current_finding and "context" in line_lower:
                context_match = re.search(r'context[:\s]+(\w+)', line, re.IGNORECASE)
                if context_match:
                    current_finding.context = context_match.group(1).strip()

            # Detect XSS type
            elif current_finding:
                if "reflected" in line_lower:
                    current_finding.xss_type = XSSType.REFLECTED.value
                elif "dom" in line_lower:
                    current_finding.xss_type = XSSType.DOM.value
                elif "stored" in line_lower:
                    current_finding.xss_type = XSSType.STORED.value
                elif "blind" in line_lower:
                    current_finding.xss_type = XSSType.BLIND.value

            # WAF detection
            if "waf" in line_lower or "firewall" in line_lower:
                waf_match = re.search(r'(waf|firewall)[:\s]+(.+)', line, re.IGNORECASE)
                if waf_match and current_finding:
                    current_finding.waf_detected = waf_match.group(2).strip()

            # Check for "no vulnerabilities" message
            if "no vulnerabilities" in line_lower or "not vulnerable" in line_lower:
                if not findings:
                    findings.append(XSSFinding(
                        target_url=target_url,
                        vulnerable=False,
                        confidence="high",
                        raw_output=line,
                    ))

        # If no findings parsed, add a "no vulnerability" finding
        if not findings:
            findings.append(XSSFinding(
                target_url=target_url,
                vulnerable=False,
                confidence="medium",
                raw_output="No XSS vulnerabilities detected by XSStrike",
            ))

        return findings

    def _store_results(
        self,
        target_url: str,
        findings: List[XSSFinding],
        raw_output: str
    ) -> None:
        """Store results in Nexus workspace."""
        timestamp = datetime.now(timezone.utc).isoformat()

        # Summarize findings
        vuln_count = sum(1 for f in findings if f.vulnerable)
        xss_types = {}
        for f in findings:
            if f.vulnerable and f.xss_type:
                xss_types[f.xss_type] = xss_types.get(f.xss_type, 0) + 1

        # Store structured JSON results
        results_data = {
            "target_url": target_url,
            "vulnerable_count": vuln_count,
            "xss_types": xss_types,
            "findings": [f.model_dump() for f in findings],
            "timestamp": timestamp,
            "scan_id": self.scan_id,
            "team_id": self.team_id,
            "tool": "xsstrike",
        }

        results_json = json.dumps(results_data, indent=2)

        # Write results
        json_path = "/assessment/xsstrike/findings.json"
        write_result = self.backend.write(json_path, results_json)

        if write_result.error:
            if "already exists" in write_result.error:
                old_content = self.backend.read(json_path)
                if old_content and not old_content.startswith("Error:"):
                    old_lines = [line.split("->", 1)[1] if "->" in line else line
                                for line in old_content.split("\n")]
                    old_content_clean = "\n".join(old_lines)
                    self.backend.edit(json_path, old_content_clean, results_json)
            else:
                logger.error(f"Failed to store results: {write_result.error}")
                raise XSSStrikeError(f"Failed to store results: {write_result.error}")

        # Store raw output
        raw_path = "/assessment/xsstrike/raw_output.txt"
        write_result = self.backend.write(raw_path, raw_output)

        if write_result.error and "already exists" not in write_result.error:
            logger.warning(f"Failed to store raw output: {write_result.error}")

        logger.info(f"Stored XSStrike results in Nexus workspace: {self.scan_id}")

    def cleanup(self) -> None:
        """Cleanup sandbox resources (only if we created it)."""
        if self.sandbox and self._owns_sandbox:
            try:
                self.sandbox.kill()
                logger.info("XSStrike sandbox cleanup completed")
            except Exception as e:
                logger.warning(f"Sandbox cleanup failed: {e}")
