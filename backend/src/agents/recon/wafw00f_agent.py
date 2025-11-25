"""
Wafw00f Agent - Web Application Firewall Detection.

Uses wafw00f tool in E2B sandbox to detect WAFs protecting target web applications.
Knowing the WAF in place is critical for adjusting exploitation techniques.

Reference:
- Issue #31: Implement wafw00f WAF Detection Agent
- E2B Template ID: dbe6pq4es6hqj31ybd38 (threatweaver-security)
- wafw00f: https://github.com/EnableSecurity/wafw00f
"""

import json
import logging
import re
from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel
from e2b import Sandbox

from src.agents.backends.nexus_backend import NexusBackend

logger = logging.getLogger(__name__)


class Wafw00fError(Exception):
    """Exceptions raised by wafw00f agent."""
    pass


class WafFinding(BaseModel):
    """Represents a WAF detection result from wafw00f."""
    target: str                         # Target URL
    waf_detected: bool                  # Whether any WAF was detected
    waf_name: Optional[str] = None      # WAF product name (e.g., "Cloudflare")
    waf_vendor: Optional[str] = None    # Vendor name
    confidence: str = "unknown"         # high, medium, low, unknown
    detection_method: Optional[str] = None  # How it was detected
    raw_output: Optional[str] = None    # Raw wafw00f output


class Wafw00fAgent:
    """
    WAF detection agent using wafw00f in E2B sandbox.

    This agent:
    1. Runs wafw00f in E2B sandbox (isolated, secure execution)
    2. Detects Web Application Firewalls on target URLs
    3. Identifies WAF vendor and product
    4. Stores results in Nexus workspace

    Storage:
        /{team_id}/{scan_id}/recon/wafw00f/findings.json
        /{team_id}/{scan_id}/recon/wafw00f/raw_output.txt

    Example:
        >>> from src.config import get_nexus_fs
        >>> from src.agents.backends.nexus_backend import NexusBackend
        >>>
        >>> nx = get_nexus_fs()
        >>> backend = NexusBackend("scan-123", "team-abc", nx)
        >>>
        >>> agent = Wafw00fAgent(
        ...     scan_id="scan-123",
        ...     team_id="team-abc",
        ...     nexus_backend=backend
        ... )
        >>> findings = agent.execute(["https://example.com"])
        >>> for f in findings:
        ...     if f.waf_detected:
        ...         print(f"WAF detected: {f.waf_name}")
    """

    # Known WAF names for better parsing
    KNOWN_WAFS = {
        "cloudflare": "Cloudflare",
        "akamai": "Akamai",
        "aws": "AWS WAF",
        "awselb": "AWS ELB",
        "awsalb": "AWS ALB",
        "sucuri": "Sucuri",
        "incapsula": "Imperva Incapsula",
        "imperva": "Imperva",
        "modsecurity": "ModSecurity",
        "f5": "F5 BIG-IP",
        "barracuda": "Barracuda",
        "fortinet": "Fortinet FortiWeb",
        "citrix": "Citrix NetScaler",
        "radware": "Radware AppWall",
        "wordfence": "Wordfence",
    }

    def __init__(
        self,
        scan_id: str,
        team_id: str,
        nexus_backend: NexusBackend,
        sandbox: Optional[Sandbox] = None,
    ):
        """
        Initialize wafw00f agent.

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
            self.sandbox = Sandbox.create(template="dbe6pq4es6hqj31ybd38", timeout=600)
            self._owns_sandbox = True
        else:
            self.sandbox = sandbox
            self._owns_sandbox = False

    def execute(
        self,
        targets: List[str],
        timeout: int = 300,
    ) -> List[WafFinding]:
        """
        Detect WAFs on target URLs.

        Args:
            targets: List of URLs to scan (e.g., ["https://example.com"])
            timeout: Execution timeout in seconds (default: 300)

        Returns:
            List of WafFinding objects for each target

        Raises:
            Wafw00fError: If execution fails or times out

        Example:
            >>> findings = agent.execute(["https://example.com", "https://test.com"])
            >>> for f in findings:
            ...     print(f"{f.target}: {f.waf_name or 'No WAF detected'}")
        """
        logger.info(f"Starting WAF detection for {len(targets)} targets")

        try:
            # Validate URLs
            for url in targets:
                self._validate_url(url)

            # Run wafw00f in E2B sandbox
            raw_output = self._run_wafw00f(targets, timeout)

            # Parse output
            findings = self._parse_output(raw_output, targets)

            # Store results in Nexus workspace
            self._store_results(targets, findings, raw_output)

            detected_count = sum(1 for f in findings if f.waf_detected)
            logger.info(f"WAF detected on {detected_count}/{len(findings)} targets")
            return findings

        except Exception as e:
            logger.error(f"wafw00f execution failed: {e}")
            raise Wafw00fError(f"WAF detection failed: {e}") from e

    def _run_wafw00f(self, targets: List[str], timeout: int) -> str:
        """Execute wafw00f in E2B sandbox."""
        # Write targets to file
        targets_content = "\n".join(targets)
        self.sandbox.files.write("/tmp/targets.txt", targets_content)

        # Build wafw00f command
        command = "wafw00f -i /tmp/targets.txt -o /tmp/wafw00f_output.txt -f text"

        logger.info(f"Running wafw00f on {len(targets)} targets")

        try:
            # First check if wafw00f is installed, if not install it
            check_result = self.sandbox.commands.run("which wafw00f", timeout=30)
            if check_result.exit_code != 0:
                logger.info("Installing wafw00f in sandbox...")
                install_result = self.sandbox.commands.run(
                    "pip install wafw00f",
                    timeout=120
                )
                if install_result.exit_code != 0:
                    raise Wafw00fError(f"Failed to install wafw00f: {install_result.stderr}")

            result = self.sandbox.commands.run(command, timeout=timeout)

            # Read output file
            try:
                output = self.sandbox.files.read("/tmp/wafw00f_output.txt")
            except Exception:
                output = result.stdout

            return output or result.stdout

        except TimeoutError as e:
            raise Wafw00fError(f"wafw00f timed out after {timeout}s") from e

    def _validate_url(self, url: str) -> None:
        """Validate URL format."""
        if not url.startswith(('http://', 'https://')):
            raise ValueError(f"URL must start with http:// or https://: {url}")

        # Basic URL validation
        pattern = r'^https?://[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9](:[0-9]+)?(/.*)?$'
        if not re.match(pattern, url):
            raise ValueError(f"Invalid URL format: {url}")

    def _parse_output(self, raw_output: str, targets: List[str]) -> List[WafFinding]:
        """Parse wafw00f output into WafFinding objects."""
        findings = []

        # Initialize findings for all targets (in case some aren't in output)
        target_findings = {url: None for url in targets}

        # Parse wafw00f output
        # Example output formats:
        # "https://example.com is behind Cloudflare (Cloudflare Inc.)"
        # "https://example.com might be behind a WAF"
        # "No WAF detected by the generic detection"

        for line in raw_output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue

            # Check for WAF detection
            waf_detected = False
            waf_name = None
            waf_vendor = None
            confidence = "unknown"
            target_url = None

            # Find which target this line is about
            for url in targets:
                if url in line:
                    target_url = url
                    break

            if not target_url:
                continue

            # Parse detection results
            line_lower = line.lower()

            if "is behind" in line_lower:
                waf_detected = True
                confidence = "high"
                # Extract WAF name from "is behind X (Y)"
                match = re.search(r'is behind\s+(.+?)(?:\s+\((.+?)\))?$', line, re.IGNORECASE)
                if match:
                    waf_name = match.group(1).strip()
                    waf_vendor = match.group(2).strip() if match.group(2) else None

            elif "might be behind" in line_lower:
                waf_detected = True
                confidence = "medium"
                # Extract potential WAF
                match = re.search(r'might be behind\s+(.+?)(?:\s+\((.+?)\))?$', line, re.IGNORECASE)
                if match:
                    waf_name = match.group(1).strip()

            elif "no waf detected" in line_lower:
                waf_detected = False
                confidence = "high"

            elif "generic detection" in line_lower and "waf" in line_lower:
                waf_detected = True
                confidence = "low"
                waf_name = "Unknown WAF"

            # Normalize WAF name if recognized
            if waf_name:
                for key, value in self.KNOWN_WAFS.items():
                    if key in waf_name.lower():
                        waf_name = value
                        break

            target_findings[target_url] = WafFinding(
                target=target_url,
                waf_detected=waf_detected,
                waf_name=waf_name,
                waf_vendor=waf_vendor,
                confidence=confidence,
                detection_method="wafw00f fingerprinting",
                raw_output=line,
            )

        # Create findings list, adding placeholder for any targets not in output
        for url in targets:
            if target_findings[url]:
                findings.append(target_findings[url])
            else:
                # Target not in output - assume no WAF or error
                findings.append(WafFinding(
                    target=url,
                    waf_detected=False,
                    confidence="unknown",
                    detection_method="wafw00f fingerprinting",
                    raw_output="No output for this target",
                ))

        return findings

    def _store_results(
        self,
        targets: List[str],
        findings: List[WafFinding],
        raw_output: str
    ) -> None:
        """Store results in Nexus workspace."""
        timestamp = datetime.now(timezone.utc).isoformat()

        # Summarize findings
        detected_wafs = {}
        for f in findings:
            if f.waf_detected and f.waf_name:
                detected_wafs[f.waf_name] = detected_wafs.get(f.waf_name, 0) + 1

        # Store structured JSON results
        results_data = {
            "targets": targets,
            "targets_count": len(targets),
            "waf_detected_count": sum(1 for f in findings if f.waf_detected),
            "detected_wafs": detected_wafs,
            "findings": [f.model_dump() for f in findings],
            "timestamp": timestamp,
            "scan_id": self.scan_id,
            "team_id": self.team_id,
            "tool": "wafw00f",
        }

        results_json = json.dumps(results_data, indent=2)

        # Write results
        json_path = "/recon/wafw00f/findings.json"
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
                raise Wafw00fError(f"Failed to store results: {write_result.error}")

        # Store raw output
        raw_path = "/recon/wafw00f/raw_output.txt"
        write_result = self.backend.write(raw_path, raw_output)

        if write_result.error and "already exists" not in write_result.error:
            logger.warning(f"Failed to store raw output: {write_result.error}")

        logger.info(f"Stored wafw00f results in Nexus workspace: {self.scan_id}")

    def cleanup(self) -> None:
        """Cleanup sandbox resources (only if we created it)."""
        if self.sandbox and self._owns_sandbox:
            try:
                self.sandbox.kill()
                logger.info("wafw00f sandbox cleanup completed")
            except Exception as e:
                logger.warning(f"Sandbox cleanup failed: {e}")
