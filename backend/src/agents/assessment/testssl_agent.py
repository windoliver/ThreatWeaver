"""
testssl.sh Agent - TLS/SSL Security Testing.

Uses testssl.sh tool in E2B sandbox to analyze TLS/SSL security configuration
of web servers. Checks for protocol versions, cipher suites, certificates,
and known vulnerabilities like Heartbleed, POODLE, ROBOT, etc.

Reference:
- Issue #33: Implement testssl.sh TLS Security Agent
- E2B Template ID: dbe6pq4es6hqj31ybd38 (threatweaver-security)
- testssl.sh: https://github.com/drwetter/testssl.sh
"""

import json
import logging
import re
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from enum import Enum

from pydantic import BaseModel
from e2b import Sandbox

from src.agents.backends.nexus_backend import NexusBackend

logger = logging.getLogger(__name__)


class TLSSeverity(str, Enum):
    """TLS vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    OK = "ok"


class TestsslError(Exception):
    """Exceptions raised by testssl agent."""
    pass


class TLSVulnerability(BaseModel):
    """Represents a TLS/SSL vulnerability finding."""
    id: str                                   # Vulnerability identifier (e.g., "heartbleed")
    name: str                                 # Human-readable name
    severity: str                             # critical, high, medium, low, info, ok
    finding: str                              # Detailed finding description
    cve: Optional[str] = None                 # CVE if applicable
    cwe: Optional[str] = None                 # CWE if applicable


class CertificateInfo(BaseModel):
    """Represents certificate information."""
    subject: Optional[str] = None
    issuer: Optional[str] = None
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    days_until_expiry: Optional[int] = None
    key_size: Optional[int] = None
    signature_algorithm: Optional[str] = None
    san: Optional[List[str]] = None           # Subject Alternative Names
    is_expired: bool = False
    is_self_signed: bool = False


class TLSFinding(BaseModel):
    """Represents complete TLS/SSL analysis results."""
    target: str                               # Target host:port
    target_ip: Optional[str] = None
    port: int = 443
    protocols: Dict[str, bool] = {}           # SSLv2, SSLv3, TLS1.0, etc.
    ciphers: Dict[str, str] = {}              # Cipher suite status
    certificate: Optional[CertificateInfo] = None
    vulnerabilities: List[TLSVulnerability] = []
    overall_rating: str = "unknown"           # A+, A, B, C, D, F
    scan_time_seconds: Optional[float] = None
    raw_output: Optional[str] = None


class TestsslAgent:
    """
    TLS/SSL security testing agent using testssl.sh in E2B sandbox.

    This agent:
    1. Runs testssl.sh in E2B sandbox (isolated, secure execution)
    2. Tests SSL/TLS protocol versions supported
    3. Analyzes cipher suite strength
    4. Checks for known vulnerabilities (Heartbleed, POODLE, etc.)
    5. Validates certificate chain and expiry
    6. Stores findings in Nexus workspace

    Storage:
        /{team_id}/{scan_id}/assessment/testssl/findings.json
        /{team_id}/{scan_id}/assessment/testssl/raw_output.json

    Example:
        >>> from src.config import get_nexus_fs
        >>> from src.agents.backends.nexus_backend import NexusBackend
        >>>
        >>> nx = get_nexus_fs()
        >>> backend = NexusBackend("scan-123", "team-abc", nx)
        >>>
        >>> agent = TestsslAgent(
        ...     scan_id="scan-123",
        ...     team_id="team-abc",
        ...     nexus_backend=backend
        ... )
        >>> findings = agent.execute("https://example.com")
        >>> print(f"TLS Rating: {findings.overall_rating}")
        >>> for vuln in findings.vulnerabilities:
        ...     print(f"  {vuln.severity}: {vuln.name}")
    """

    # Known TLS/SSL vulnerabilities to check
    VULN_CHECKS = [
        "heartbleed",
        "ccs-injection",
        "ticketbleed",
        "robot",
        "secure_renego",
        "secure_client_renego",
        "crime",
        "breach",
        "poodle_ssl",
        "fallback_scsv",
        "sweet32",
        "freak",
        "drown",
        "logjam",
        "beast",
        "lucky13",
        "rc4",
    ]

    def __init__(
        self,
        scan_id: str,
        team_id: str,
        nexus_backend: NexusBackend,
        sandbox: Optional[Sandbox] = None,
    ):
        """
        Initialize testssl agent.

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
        target: str,
        port: int = 443,
        check_vulnerabilities: bool = True,
        check_protocols: bool = True,
        check_ciphers: bool = True,
        check_certificate: bool = True,
        timeout: int = 600,
    ) -> TLSFinding:
        """
        Test TLS/SSL security configuration of a target.

        Args:
            target: Target hostname or URL (e.g., "example.com" or "https://example.com")
            port: Port to test (default: 443)
            check_vulnerabilities: Test for known vulnerabilities (default: True)
            check_protocols: Check supported protocols (default: True)
            check_ciphers: Analyze cipher suites (default: True)
            check_certificate: Validate certificate (default: True)
            timeout: Execution timeout in seconds (default: 600)

        Returns:
            TLSFinding with complete analysis results

        Raises:
            TestsslError: If execution fails or times out

        Example:
            >>> finding = agent.execute("example.com", port=443)
            >>> print(f"Rating: {finding.overall_rating}")
            >>> for vuln in finding.vulnerabilities:
            ...     if vuln.severity in ["critical", "high"]:
            ...         print(f"ALERT: {vuln.name}")
        """
        # Normalize target (remove https://)
        host = self._normalize_target(target)
        logger.info(f"Starting TLS security test for {host}:{port}")

        try:
            # Run testssl.sh in E2B sandbox
            raw_output = self._run_testssl(
                host=host,
                port=port,
                check_vulnerabilities=check_vulnerabilities,
                check_protocols=check_protocols,
                check_ciphers=check_ciphers,
                check_certificate=check_certificate,
                timeout=timeout,
            )

            # Parse output into structured findings
            finding = self._parse_output(raw_output, host, port)

            # Store results in Nexus workspace
            self._store_results(host, port, finding, raw_output)

            vuln_count = len([v for v in finding.vulnerabilities if v.severity in ["critical", "high"]])
            logger.info(f"TLS test completed for {host}:{port} - Rating: {finding.overall_rating}, High+ vulns: {vuln_count}")
            return finding

        except Exception as e:
            logger.error(f"testssl execution failed: {e}")
            raise TestsslError(f"TLS security test failed: {e}") from e

    def _normalize_target(self, target: str) -> str:
        """Normalize target to hostname only."""
        # Remove protocol prefix
        if target.startswith("https://"):
            target = target[8:]
        elif target.startswith("http://"):
            target = target[7:]

        # Remove path and trailing slash
        target = target.split("/")[0]

        # Remove port if present
        if ":" in target:
            target = target.split(":")[0]

        return target

    def _run_testssl(
        self,
        host: str,
        port: int,
        check_vulnerabilities: bool,
        check_protocols: bool,
        check_ciphers: bool,
        check_certificate: bool,
        timeout: int,
    ) -> str:
        """Execute testssl.sh in E2B sandbox."""
        # Build testssl command
        cmd_parts = [
            "/opt/testssl.sh/testssl.sh",
            "--jsonfile /tmp/testssl_output.json",
            "--quiet",
            "--color 0",  # No colors in output
        ]

        # Add specific checks if not doing full scan
        if not (check_vulnerabilities and check_protocols and check_ciphers and check_certificate):
            if check_protocols:
                cmd_parts.append("-p")  # Protocols
            if check_ciphers:
                cmd_parts.append("-E")  # Cipher suites
            if check_certificate:
                cmd_parts.append("-S")  # Server preferences & certificate
            if check_vulnerabilities:
                cmd_parts.append("-U")  # All vulnerabilities

        # Add target
        cmd_parts.append(f"{host}:{port}")

        command = " ".join(cmd_parts)
        logger.info(f"Running testssl.sh: {command[:80]}...")

        try:
            # First check if testssl.sh is installed, if not install it
            check_result = self.sandbox.commands.run("test -f /opt/testssl.sh/testssl.sh", timeout=30)
            if check_result.exit_code != 0:
                logger.info("Installing testssl.sh in sandbox...")
                install_cmds = [
                    "git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh",
                    "chmod +x /opt/testssl.sh/testssl.sh",
                ]
                for cmd in install_cmds:
                    install_result = self.sandbox.commands.run(cmd, timeout=120)
                    if install_result.exit_code != 0:
                        logger.warning(f"Install command failed: {cmd}")

            result = self.sandbox.commands.run(
                command,
                timeout=timeout,
            )

            # Read JSON output file
            try:
                json_output = self.sandbox.files.read("/tmp/testssl_output.json")
                return json_output
            except Exception:
                # Fall back to stdout
                return result.stdout + "\n" + result.stderr

        except TimeoutError as e:
            raise TestsslError(f"testssl.sh timed out after {timeout}s") from e

    def _parse_output(self, raw_output: str, host: str, port: int) -> TLSFinding:
        """Parse testssl.sh JSON output into TLSFinding."""
        finding = TLSFinding(
            target=f"{host}:{port}",
            port=port,
        )

        try:
            # Parse JSON output
            data = json.loads(raw_output)

            # testssl.sh JSON is an array of findings
            if isinstance(data, list):
                for item in data:
                    self._process_finding_item(item, finding)
            elif isinstance(data, dict):
                # Sometimes wrapped in a dict
                findings_list = data.get("scanResult", []) or data.get("findings", [])
                for item in findings_list:
                    self._process_finding_item(item, finding)

        except json.JSONDecodeError:
            # Fall back to text parsing
            logger.warning("JSON parsing failed, falling back to text parsing")
            self._parse_text_output(raw_output, finding)

        finding.raw_output = raw_output[:5000]  # Truncate for storage
        self._calculate_rating(finding)

        return finding

    def _process_finding_item(self, item: Dict[str, Any], finding: TLSFinding) -> None:
        """Process a single finding item from testssl.sh JSON output."""
        finding_id = item.get("id", "")
        severity = item.get("severity", "INFO").lower()
        finding_text = item.get("finding", "")

        # Protocol checks
        if finding_id.startswith("SSLv") or finding_id.startswith("TLS"):
            offered = "offered" in finding_text.lower() or "yes" in finding_text.lower()
            finding.protocols[finding_id] = offered

        # Certificate info
        elif finding_id == "cert_commonName":
            if finding.certificate is None:
                finding.certificate = CertificateInfo()
            finding.certificate.subject = finding_text

        elif finding_id == "cert_caIssuers":
            if finding.certificate is None:
                finding.certificate = CertificateInfo()
            finding.certificate.issuer = finding_text

        elif finding_id == "cert_notBefore":
            if finding.certificate is None:
                finding.certificate = CertificateInfo()
            finding.certificate.valid_from = finding_text

        elif finding_id == "cert_notAfter":
            if finding.certificate is None:
                finding.certificate = CertificateInfo()
            finding.certificate.valid_until = finding_text

        elif finding_id == "cert_keySize":
            if finding.certificate is None:
                finding.certificate = CertificateInfo()
            try:
                finding.certificate.key_size = int(re.search(r'\d+', finding_text).group())
            except (AttributeError, ValueError):
                pass

        # Vulnerability checks
        elif finding_id in self.VULN_CHECKS or "vulnerability" in finding_id.lower():
            vuln_severity = self._map_severity(severity)
            if vuln_severity != "ok":  # Only add actual vulnerabilities
                finding.vulnerabilities.append(TLSVulnerability(
                    id=finding_id,
                    name=finding_id.replace("_", " ").title(),
                    severity=vuln_severity,
                    finding=finding_text,
                    cve=item.get("cve"),
                    cwe=item.get("cwe"),
                ))

        # Cipher suites
        elif "cipher" in finding_id.lower():
            finding.ciphers[finding_id] = f"{severity}: {finding_text[:100]}"

    def _parse_text_output(self, raw_output: str, finding: TLSFinding) -> None:
        """Parse text output when JSON is not available."""
        lines = raw_output.split('\n')

        for line in lines:
            line_lower = line.lower()

            # Check for vulnerabilities
            for vuln in self.VULN_CHECKS:
                if vuln in line_lower:
                    is_vulnerable = "vulnerable" in line_lower or "not ok" in line_lower
                    if is_vulnerable:
                        finding.vulnerabilities.append(TLSVulnerability(
                            id=vuln,
                            name=vuln.replace("_", " ").title(),
                            severity="high" if vuln in ["heartbleed", "robot", "drown"] else "medium",
                            finding=line.strip(),
                        ))

            # Check protocols
            for proto in ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]:
                if proto.lower() in line_lower:
                    offered = "offered" in line_lower or "yes" in line_lower
                    finding.protocols[proto] = offered

    def _map_severity(self, severity: str) -> str:
        """Map testssl severity to our severity levels."""
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "warn": "medium",
            "info": "info",
            "ok": "ok",
        }
        return severity_map.get(severity.lower(), "info")

    def _calculate_rating(self, finding: TLSFinding) -> None:
        """Calculate overall TLS security rating."""
        # Count issues by severity
        critical = sum(1 for v in finding.vulnerabilities if v.severity == "critical")
        high = sum(1 for v in finding.vulnerabilities if v.severity == "high")
        medium = sum(1 for v in finding.vulnerabilities if v.severity == "medium")

        # Check for weak protocols
        weak_protocols = 0
        for proto, offered in finding.protocols.items():
            if offered and proto in ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]:
                weak_protocols += 1

        # Calculate rating
        if critical > 0:
            finding.overall_rating = "F"
        elif high > 0 or weak_protocols >= 2:
            finding.overall_rating = "D"
        elif medium > 0 or weak_protocols >= 1:
            finding.overall_rating = "C"
        elif finding.protocols.get("TLSv1.3", False):
            finding.overall_rating = "A"
        elif finding.protocols.get("TLSv1.2", False):
            finding.overall_rating = "B"
        else:
            finding.overall_rating = "B-"

    def _store_results(
        self,
        host: str,
        port: int,
        finding: TLSFinding,
        raw_output: str
    ) -> None:
        """Store results in Nexus workspace."""
        timestamp = datetime.now(timezone.utc).isoformat()

        # Summarize vulnerabilities by severity
        vuln_summary = {}
        for v in finding.vulnerabilities:
            vuln_summary[v.severity] = vuln_summary.get(v.severity, 0) + 1

        # Store structured JSON results
        results_data = {
            "target": f"{host}:{port}",
            "overall_rating": finding.overall_rating,
            "protocols": finding.protocols,
            "certificate": finding.certificate.model_dump() if finding.certificate else None,
            "vulnerability_summary": vuln_summary,
            "vulnerabilities": [v.model_dump() for v in finding.vulnerabilities],
            "timestamp": timestamp,
            "scan_id": self.scan_id,
            "team_id": self.team_id,
            "tool": "testssl.sh",
        }

        results_json = json.dumps(results_data, indent=2)

        # Write results
        json_path = "/assessment/testssl/findings.json"
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
                raise TestsslError(f"Failed to store results: {write_result.error}")

        # Store raw output
        raw_path = "/assessment/testssl/raw_output.json"
        write_result = self.backend.write(raw_path, raw_output[:50000])  # Truncate

        if write_result.error and "already exists" not in write_result.error:
            logger.warning(f"Failed to store raw output: {write_result.error}")

        logger.info(f"Stored testssl results in Nexus workspace: {self.scan_id}")

    def cleanup(self) -> None:
        """Cleanup sandbox resources (only if we created it)."""
        if self.sandbox and self._owns_sandbox:
            try:
                self.sandbox.kill()
                logger.info("testssl sandbox cleanup completed")
            except Exception as e:
                logger.warning(f"Sandbox cleanup failed: {e}")
