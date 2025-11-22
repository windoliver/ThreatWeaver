"""
HTTPx Agent - HTTP/HTTPS Probing.

Uses HTTPx tool in E2B sandbox to probe discovered subdomains and identify live hosts.
Takes Subfinder output as input and checks which hosts respond to HTTP/HTTPS.

Reference:
- Issue #14: Implement HTTPx Agent
- E2B Template ID: dbe6pq4es6hqj31ybd38 (threatweaver-security)
- HTTPx: https://github.com/projectdiscovery/httpx
"""

import json
import logging
import re
from datetime import datetime
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse

from e2b import Sandbox

from src.agents.backends.nexus_backend import NexusBackend

logger = logging.getLogger(__name__)


class HTTPxError(Exception):
    """Exceptions raised by HTTPx agent."""
    pass


class HTTPxAgent:
    """
    HTTP/HTTPS probing agent using HTTPx in E2B sandbox.

    This agent:
    1. Takes subdomain list (from Subfinder or other sources)
    2. Runs HTTPx in E2B sandbox to probe HTTP/HTTPS services
    3. Parses probe results (status codes, titles, tech stack, etc.)
    4. Identifies live hosts
    5. Stores results in Nexus workspace

    Storage:
        /{team_id}/{scan_id}/recon/httpx/live_hosts.json
        /{team_id}/{scan_id}/recon/httpx/raw_output.txt

    Example:
        >>> from src.config import get_nexus_fs
        >>> from src.agents.backends.nexus_backend import NexusBackend
        >>>
        >>> nx = get_nexus_fs()
        >>> backend = NexusBackend("scan-123", "team-abc", nx)
        >>>
        >>> agent = HTTPxAgent(
        ...     scan_id="scan-123",
        ...     team_id="team-abc",
        ...     nexus_backend=backend
        ... )
        >>> subdomains = ["www.example.com", "api.example.com", "dead.example.com"]
        >>> live_hosts = agent.execute(subdomains)
        >>> print(f"Found {len(live_hosts)} live hosts")
    """

    def __init__(
        self,
        scan_id: str,
        team_id: str,
        nexus_backend: NexusBackend,
        sandbox: Optional[Sandbox] = None,
    ):
        """
        Initialize HTTPx agent.

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
        targets: List[str],
        timeout: int = 300,
        threads: int = 50,
        follow_redirects: bool = True,
        tech_detect: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Probe targets for HTTP/HTTPS services.

        Args:
            targets: List of domains/subdomains to probe (e.g., ["example.com", "www.example.com"])
            timeout: Execution timeout in seconds (default: 5 minutes)
            threads: Number of concurrent threads (default: 50)
            follow_redirects: Follow HTTP redirects (default: True)
            tech_detect: Enable technology detection (default: True)

        Returns:
            List of live host dictionaries with probe results

        Raises:
            HTTPxError: If execution fails or times out

        Example:
            >>> live_hosts = agent.execute(["www.papergen.ai", "api.papergen.ai"])
            >>> for host in live_hosts:
            ...     print(f"{host['url']} - {host['status_code']} - {host['title']}")
        """
        logger.info(f"Starting HTTP probing for {len(targets)} targets")

        if not targets:
            logger.warning("No targets provided to HTTPx agent")
            return []

        try:
            # Validate targets
            self._validate_targets(targets)

            # Create temp file with targets in E2B sandbox
            targets_content = "\n".join(targets)
            self.sandbox.files.write("/tmp/httpx_targets.txt", targets_content)

            # Run HTTPx in E2B sandbox
            result = self._run_httpx(
                timeout=timeout,
                threads=threads,
                follow_redirects=follow_redirects,
                tech_detect=tech_detect,
            )

            # Parse JSON output
            live_hosts = self._parse_output(result.stdout)

            # Store results in Nexus workspace
            self._store_results(targets, live_hosts, result.stdout)

            logger.info(f"Found {len(live_hosts)} live hosts out of {len(targets)} targets")
            return live_hosts

        except Exception as e:
            logger.error(f"HTTPx execution failed: {e}")
            raise HTTPxError(f"HTTP probing failed: {e}") from e

    def _run_httpx(
        self,
        timeout: int,
        threads: int,
        follow_redirects: bool,
        tech_detect: bool,
    ):
        """Execute HTTPx in E2B sandbox."""
        # HTTPx command with JSON output for structured parsing
        # -l: input file
        # -json: JSON output
        # -silent: suppress banner
        # -status-code: include status code
        # -title: include page title
        # -tech-detect: detect technologies
        # -follow-redirects: follow redirects
        # -threads: concurrent threads
        command_parts = [
            "httpx",
            "-l /tmp/httpx_targets.txt",
            "-json",
            "-silent",
            "-status-code",
            "-title",
            "-web-server",
            "-content-length",
            f"-threads {threads}",
        ]

        if follow_redirects:
            command_parts.append("-follow-redirects")

        if tech_detect:
            command_parts.append("-tech-detect")

        command = " ".join(command_parts)

        try:
            result = self.sandbox.commands.run(command, timeout=timeout)

            # HTTPx exits with 0 even if no hosts are live, so we don't check exit code strictly
            # Just log stderr if present
            if result.stderr:
                logger.debug(f"HTTPx stderr: {result.stderr}")

            return result

        except TimeoutError as e:
            raise HTTPxError(f"HTTPx timed out after {timeout}s") from e

    def _validate_targets(self, targets: List[str]) -> None:
        """Validate target list."""
        if not isinstance(targets, list):
            raise ValueError("Targets must be a list")

        if len(targets) == 0:
            raise ValueError("Targets list cannot be empty")

        # Basic validation of each target
        for target in targets:
            if not target or not isinstance(target, str):
                raise ValueError(f"Invalid target: {target}")

            # Remove protocol if present for validation
            clean_target = target.replace("http://", "").replace("https://", "").split("/")[0]

            # Simple domain validation (same as Subfinder)
            if len(clean_target) > 253:
                raise ValueError(f"Target too long: {target}")

            pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
            if not re.match(pattern, clean_target):
                raise ValueError(f"Invalid target format: {target}")

    def _parse_output(self, stdout: str) -> List[Dict[str, Any]]:
        """
        Parse HTTPx JSON output.

        HTTPx outputs one JSON object per line for each live host.
        """
        live_hosts = []

        if not stdout.strip():
            return live_hosts

        for line in stdout.strip().split('\n'):
            line = line.strip()
            if not line:
                continue

            try:
                host_data = json.loads(line)

                # Extract relevant fields
                parsed_host = {
                    "url": host_data.get("url", ""),
                    "host": host_data.get("host", ""),
                    "status_code": host_data.get("status_code", 0),
                    "title": host_data.get("title", ""),
                    "web_server": host_data.get("webserver", ""),
                    "content_length": host_data.get("content_length", 0),
                    "technologies": host_data.get("tech", []),
                    "scheme": host_data.get("scheme", ""),
                    "port": host_data.get("port", ""),
                }

                # Add timestamp
                parsed_host["probed_at"] = datetime.utcnow().isoformat()

                live_hosts.append(parsed_host)

            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse HTTPx JSON line: {line[:100]}... Error: {e}")
                continue

        return live_hosts

    def _store_results(
        self,
        targets: List[str],
        live_hosts: List[Dict[str, Any]],
        raw_output: str
    ) -> None:
        """Store results in Nexus workspace."""
        timestamp = datetime.utcnow().isoformat()

        # Store structured JSON results
        results_data = {
            "targets_count": len(targets),
            "live_hosts_count": len(live_hosts),
            "live_hosts": live_hosts,
            "timestamp": timestamp,
            "scan_id": self.scan_id,
            "team_id": self.team_id,
            "tool": "httpx",
            "version": "1.3.7"
        }

        results_json = json.dumps(results_data, indent=2)

        # Try to write, if file exists read and replace entire content
        json_path = "/recon/httpx/live_hosts.json"
        write_result = self.backend.write(json_path, results_json)

        if write_result.error:
            if "already exists" in write_result.error:
                # File exists, read current content and replace it entirely
                old_content = self.backend.read(json_path)
                if old_content and not old_content.startswith("Error:"):
                    # Strip line numbers from read result (format: "     1→content")
                    old_lines = [line.split("→", 1)[1] if "→" in line else line
                                for line in old_content.split("\n")]
                    old_content_clean = "\n".join(old_lines)

                    edit_result = self.backend.edit(json_path, old_content_clean, results_json)
                    if edit_result.error:
                        logger.error(f"Failed to update results: {edit_result.error}")
                        raise HTTPxError(f"Failed to update results: {edit_result.error}")
                else:
                    logger.error(f"Failed to read existing results")
                    raise HTTPxError(f"Failed to read existing results")
            else:
                logger.error(f"Failed to store results: {write_result.error}")
                raise HTTPxError(f"Failed to store results: {write_result.error}")

        # Store raw output for debugging
        raw_path = "/recon/httpx/raw_output.txt"
        write_result = self.backend.write(raw_path, raw_output)

        if write_result.error:
            if "already exists" in write_result.error:
                # File exists, read current content and replace it entirely
                old_content = self.backend.read(raw_path)
                if old_content and not old_content.startswith("Error:"):
                    # Strip line numbers from read result
                    old_lines = [line.split("→", 1)[1] if "→" in line else line
                                for line in old_content.split("\n")]
                    old_content_clean = "\n".join(old_lines)

                    self.backend.edit(raw_path, old_content_clean, raw_output)
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
