"""
Subfinder Agent - Subdomain Discovery.

Uses Subfinder tool in E2B sandbox to discover subdomains for target domains.
Results are stored in Nexus workspace for downstream agents.

Reference:
- Issue #13: Implement Subfinder Agent
- E2B Template ID: dbe6pq4es6hqj31ybd38 (threatweaver-security)
- Subfinder: https://github.com/projectdiscovery/subfinder
"""

import json
import logging
import re
from datetime import datetime
from typing import List, Optional

from e2b import Sandbox

from src.agents.backends.nexus_backend import NexusBackend

logger = logging.getLogger(__name__)


class SubfinderError(Exception):
    """Exceptions raised by Subfinder agent."""
    pass


class SubfinderAgent:
    """
    Subdomain discovery agent using Subfinder in E2B sandbox.

    This agent:
    1. Runs Subfinder in E2B sandbox (isolated, secure execution)
    2. Parses subdomain results
    3. Filters wildcards and duplicates
    4. Stores results in Nexus workspace

    Storage:
        /{team_id}/{scan_id}/recon/subfinder/subdomains.json
        /{team_id}/{scan_id}/recon/subfinder/raw_output.txt

    Example:
        >>> from src.config import get_nexus_fs
        >>> from src.agents.backends.nexus_backend import NexusBackend
        >>>
        >>> nx = get_nexus_fs()
        >>> backend = NexusBackend("scan-123", "team-abc", nx)
        >>>
        >>> agent = SubfinderAgent(
        ...     scan_id="scan-123",
        ...     team_id="team-abc",
        ...     nexus_backend=backend
        ... )
        >>> subdomains = agent.execute("example.com")
        >>> print(f"Found {len(subdomains)} subdomains")
    """

    def __init__(
        self,
        scan_id: str,
        team_id: str,
        nexus_backend: NexusBackend,
        sandbox: Optional[Sandbox] = None,
    ):
        """
        Initialize Subfinder agent.

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
            self._owns_sandbox = True  # We created it, so we'll clean it up
        else:
            self.sandbox = sandbox
            self._owns_sandbox = False  # Provided externally, don't clean up

    def execute(
        self,
        domain: str,
        timeout: int = 300,
        filter_wildcards: bool = True,
    ) -> List[str]:
        """
        Discover subdomains for target domain.

        Args:
            domain: Target domain (e.g., "example.com")
            timeout: Execution timeout in seconds (default: 5 minutes)
            filter_wildcards: Remove wildcard DNS entries (default: True)

        Returns:
            List of discovered subdomains

        Raises:
            SubfinderError: If execution fails or times out

        Example:
            >>> subdomains = agent.execute("hackerone.com")
            >>> print(subdomains)
            ['www.hackerone.com', 'api.hackerone.com', 'docs.hackerone.com']
        """
        logger.info(f"Starting subdomain discovery for {domain}")

        try:
            # Validate domain
            self._validate_domain(domain)

            # Run Subfinder in E2B sandbox
            result = self._run_subfinder(domain, timeout)

            # Parse and clean results
            subdomains = self._parse_output(result.stdout, filter_wildcards)

            # Store results in Nexus workspace
            self._store_results(domain, subdomains, result.stdout)

            logger.info(f"Found {len(subdomains)} subdomains for {domain}")
            return subdomains

        except Exception as e:
            logger.error(f"Subfinder execution failed for {domain}: {e}")
            raise SubfinderError(f"Subdomain discovery failed: {e}") from e

    def _run_subfinder(self, domain: str, timeout: int):
        """Execute Subfinder in E2B sandbox."""
        command = f"subfinder -d {domain} -silent"

        try:
            result = self.sandbox.commands.run(command, timeout=timeout)

            if result.exit_code != 0:
                raise SubfinderError(
                    f"Subfinder returned exit code {result.exit_code}: {result.stderr}"
                )

            return result

        except TimeoutError as e:
            raise SubfinderError(f"Subfinder timed out after {timeout}s") from e

    def _validate_domain(self, domain: str) -> None:
        """Validate domain format."""
        # Check length first (RFC 1035: max 253 characters)
        if len(domain) > 253:
            raise ValueError(f"Domain too long: {domain} (max 253 characters)")

        # Simple domain validation (RFC 1035)
        pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"

        if not re.match(pattern, domain):
            raise ValueError(f"Invalid domain format: {domain}")

    def _parse_output(
        self,
        stdout: str,
        filter_wildcards: bool = True
    ) -> List[str]:
        """Parse Subfinder output and clean results."""
        # Remove ANSI color codes
        ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
        clean_output = ansi_escape.sub('', stdout)

        # Split into lines and filter
        subdomains = []
        for line in clean_output.strip().split('\n'):
            subdomain = line.strip()

            if not subdomain:
                continue

            # Filter wildcards
            if filter_wildcards and subdomain.startswith('*'):
                continue

            subdomains.append(subdomain)

        # Remove duplicates while preserving order
        seen = set()
        unique_subdomains = []
        for sub in subdomains:
            if sub not in seen:
                seen.add(sub)
                unique_subdomains.append(sub)

        return unique_subdomains

    def _store_results(
        self,
        domain: str,
        subdomains: List[str],
        raw_output: str
    ) -> None:
        """Store results in Nexus workspace."""
        timestamp = datetime.utcnow().isoformat()

        # Store structured JSON results
        results_data = {
            "domain": domain,
            "subdomains": subdomains,
            "count": len(subdomains),
            "timestamp": timestamp,
            "scan_id": self.scan_id,
            "team_id": self.team_id,
            "tool": "subfinder",
            "version": "2.6.3"
        }

        results_json = json.dumps(results_data, indent=2)
        write_result = self.backend.write(
            "/recon/subfinder/subdomains.json",
            results_json
        )

        if write_result.error:
            logger.error(f"Failed to store results: {write_result.error}")
            raise SubfinderError(f"Failed to store results: {write_result.error}")

        # Store raw output for debugging
        write_result = self.backend.write(
            "/recon/subfinder/raw_output.txt",
            raw_output
        )

        if write_result.error:
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
