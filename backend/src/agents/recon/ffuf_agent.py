"""
Ffuf Agent - Directory and File Brute-Force Discovery.

Uses ffuf (Fuzz Faster U Fool) tool in E2B sandbox to discover hidden
directories, files, and endpoints on target web applications.

Reference:
- Issue #30: Implement ffuf Directory Brute-Force Agent
- E2B Template ID: dbe6pq4es6hqj31ybd38 (threatweaver-security)
- ffuf: https://github.com/ffuf/ffuf
"""

import json
import logging
import re
from datetime import datetime
from typing import List, Optional
from enum import Enum

from pydantic import BaseModel
from e2b import Sandbox

from src.agents.backends.nexus_backend import NexusBackend

logger = logging.getLogger(__name__)


class FfufError(Exception):
    """Exceptions raised by Ffuf agent."""
    pass


class WordlistType(str, Enum):
    """Predefined wordlist types."""
    COMMON = "common"           # ~4600 entries - fast, common paths
    DIRB_COMMON = "dirb"        # ~4600 entries - dirb's common.txt
    BIG = "big"                 # ~20000 entries - comprehensive
    RAFT_DIRS = "raft-dirs"     # ~30000 entries - raft directory list
    CUSTOM = "custom"           # User-provided wordlist


class FfufFinding(BaseModel):
    """Represents a discovered path/file from ffuf."""
    url: str                            # Full discovered URL
    path: str                           # Path component (e.g., /admin)
    status_code: int                    # HTTP status code
    content_length: int                 # Response size in bytes
    content_type: Optional[str] = None  # MIME type
    redirect_location: Optional[str] = None  # Location header if 3xx
    words: int = 0                      # Word count in response
    lines: int = 0                      # Line count in response
    duration_ms: Optional[int] = None   # Request duration


class FfufAgent:
    """
    Directory brute-force agent using ffuf in E2B sandbox.

    This agent:
    1. Runs ffuf in E2B sandbox (isolated, secure execution)
    2. Uses common wordlists (SecLists) for discovery
    3. Filters results by status code and size
    4. Stores discovered paths in Nexus workspace

    Storage:
        /{team_id}/{scan_id}/recon/ffuf/findings.json
        /{team_id}/{scan_id}/recon/ffuf/raw_output.json

    Example:
        >>> from src.config import get_nexus_fs
        >>> from src.agents.backends.nexus_backend import NexusBackend
        >>>
        >>> nx = get_nexus_fs()
        >>> backend = NexusBackend("scan-123", "team-abc", nx)
        >>>
        >>> agent = FfufAgent(
        ...     scan_id="scan-123",
        ...     team_id="team-abc",
        ...     nexus_backend=backend
        ... )
        >>> findings = agent.execute("https://example.com")
        >>> print(f"Found {len(findings)} hidden paths")
    """

    # Wordlist paths in E2B sandbox (SecLists pre-installed)
    WORDLIST_PATHS = {
        WordlistType.COMMON: "/usr/share/seclists/Discovery/Web-Content/common.txt",
        WordlistType.DIRB_COMMON: "/usr/share/seclists/Discovery/Web-Content/common.txt",
        WordlistType.BIG: "/usr/share/seclists/Discovery/Web-Content/big.txt",
        WordlistType.RAFT_DIRS: "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    }

    def __init__(
        self,
        scan_id: str,
        team_id: str,
        nexus_backend: NexusBackend,
        sandbox: Optional[Sandbox] = None,
    ):
        """
        Initialize ffuf agent.

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
            self.sandbox = Sandbox.create(template="dbe6pq4es6hqj31ybd38", timeout=3600)
            self._owns_sandbox = True
        else:
            self.sandbox = sandbox
            self._owns_sandbox = False

    def execute(
        self,
        target_url: str,
        wordlist: WordlistType = WordlistType.COMMON,
        extensions: Optional[List[str]] = None,
        threads: int = 40,
        rate_limit: int = 0,
        match_codes: Optional[List[int]] = None,
        filter_codes: Optional[List[int]] = None,
        filter_size: Optional[int] = None,
        timeout: int = 600,
        recursion: bool = False,
        recursion_depth: int = 1,
    ) -> List[FfufFinding]:
        """
        Discover hidden directories and files on target.

        Args:
            target_url: Base URL to scan (e.g., "https://example.com")
            wordlist: Wordlist type to use (default: COMMON)
            extensions: File extensions to append (e.g., [".php", ".bak"])
            threads: Number of concurrent threads (default: 40)
            rate_limit: Requests per second, 0 = unlimited (default: 0)
            match_codes: Only show these status codes (default: 200,204,301,302,307,401,403,405)
            filter_codes: Hide these status codes (default: None)
            filter_size: Hide responses of this size (default: None)
            timeout: Execution timeout in seconds (default: 600)
            recursion: Enable recursive scanning (default: False)
            recursion_depth: Recursion depth if enabled (default: 1)

        Returns:
            List of FfufFinding objects for discovered paths

        Raises:
            FfufError: If execution fails or times out

        Example:
            >>> findings = agent.execute(
            ...     "https://example.com",
            ...     wordlist=WordlistType.COMMON,
            ...     extensions=[".php", ".bak"]
            ... )
            >>> for f in findings:
            ...     print(f"{f.status_code} {f.path} ({f.content_length} bytes)")
        """
        logger.info(f"Starting directory brute-force for {target_url}")

        try:
            # Validate URL
            self._validate_url(target_url)

            # Set default match codes
            if match_codes is None:
                match_codes = [200, 204, 301, 302, 307, 401, 403, 405]

            # Run ffuf in E2B sandbox
            raw_output = self._run_ffuf(
                target_url=target_url,
                wordlist=wordlist,
                extensions=extensions,
                threads=threads,
                rate_limit=rate_limit,
                match_codes=match_codes,
                filter_codes=filter_codes,
                filter_size=filter_size,
                timeout=timeout,
                recursion=recursion,
                recursion_depth=recursion_depth,
            )

            # Parse JSON output
            findings = self._parse_output(raw_output, target_url)

            # Store results in Nexus workspace
            self._store_results(target_url, findings, raw_output)

            logger.info(f"Found {len(findings)} paths for {target_url}")
            return findings

        except Exception as e:
            logger.error(f"ffuf execution failed for {target_url}: {e}")
            raise FfufError(f"Directory brute-force failed: {e}") from e

    def _run_ffuf(
        self,
        target_url: str,
        wordlist: WordlistType,
        extensions: Optional[List[str]],
        threads: int,
        rate_limit: int,
        match_codes: List[int],
        filter_codes: Optional[List[int]],
        filter_size: Optional[int],
        timeout: int,
        recursion: bool,
        recursion_depth: int,
    ) -> str:
        """Execute ffuf in E2B sandbox."""
        # Get wordlist path
        wordlist_path = self.WORDLIST_PATHS.get(wordlist)
        if not wordlist_path:
            wordlist_path = self.WORDLIST_PATHS[WordlistType.COMMON]

        # Build ffuf command
        # Ensure URL ends with FUZZ keyword
        fuzz_url = target_url.rstrip('/') + '/FUZZ'

        cmd_parts = [
            "ffuf",
            f"-u '{fuzz_url}'",
            f"-w {wordlist_path}",
            f"-t {threads}",
            "-o /tmp/ffuf_output.json",
            "-of json",  # JSON output format
            "-s",  # Silent mode (no banner)
        ]

        # Add extensions
        if extensions:
            ext_str = ",".join(e.lstrip('.') for e in extensions)
            cmd_parts.append(f"-e '.{ext_str}'")

        # Add rate limiting
        if rate_limit > 0:
            cmd_parts.append(f"-rate {rate_limit}")

        # Add match codes
        mc_str = ",".join(str(c) for c in match_codes)
        cmd_parts.append(f"-mc {mc_str}")

        # Add filter codes
        if filter_codes:
            fc_str = ",".join(str(c) for c in filter_codes)
            cmd_parts.append(f"-fc {fc_str}")

        # Add filter size
        if filter_size is not None:
            cmd_parts.append(f"-fs {filter_size}")

        # Add recursion
        if recursion:
            cmd_parts.append("-recursion")
            cmd_parts.append(f"-recursion-depth {recursion_depth}")

        command = " ".join(cmd_parts)
        logger.info(f"Running ffuf: {command}")

        try:
            # First check if ffuf is installed, if not install it
            check_result = self.sandbox.commands.run("which ffuf", timeout=30)
            if check_result.exit_code != 0:
                logger.info("Installing ffuf in sandbox...")
                install_result = self.sandbox.commands.run(
                    "go install github.com/ffuf/ffuf/v2@latest && cp ~/go/bin/ffuf /usr/local/bin/",
                    timeout=120
                )
                if install_result.exit_code != 0:
                    raise FfufError(f"Failed to install ffuf: {install_result.stderr}")

            # Check if wordlist exists, if not download SecLists
            check_wl = self.sandbox.commands.run(f"test -f {wordlist_path}", timeout=10)
            if check_wl.exit_code != 0:
                logger.info("Downloading SecLists wordlists...")
                # Use a smaller common wordlist if SecLists not available
                self.sandbox.commands.run(
                    "mkdir -p /usr/share/seclists/Discovery/Web-Content && "
                    "curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt "
                    "-o /usr/share/seclists/Discovery/Web-Content/common.txt",
                    timeout=60
                )

            result = self.sandbox.commands.run(command, timeout=timeout)

            # ffuf returns non-zero on no results, check output file
            output_content = self.sandbox.files.read("/tmp/ffuf_output.json")

            if not output_content:
                # Return empty results JSON
                return '{"results": []}'

            return output_content

        except TimeoutError as e:
            raise FfufError(f"ffuf timed out after {timeout}s") from e

    def _validate_url(self, url: str) -> None:
        """Validate URL format."""
        if not url.startswith(('http://', 'https://')):
            raise ValueError(f"URL must start with http:// or https://: {url}")

        # Basic URL validation
        pattern = r'^https?://[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9](:[0-9]+)?(/.*)?$'
        if not re.match(pattern, url):
            raise ValueError(f"Invalid URL format: {url}")

    def _parse_output(self, raw_output: str, target_url: str) -> List[FfufFinding]:
        """Parse ffuf JSON output into FfufFinding objects."""
        findings = []

        try:
            data = json.loads(raw_output)
            results = data.get("results", [])

            for r in results:
                finding = FfufFinding(
                    url=r.get("url", ""),
                    path="/" + r.get("input", {}).get("FUZZ", ""),
                    status_code=r.get("status", 0),
                    content_length=r.get("length", 0),
                    content_type=r.get("content-type", None),
                    redirect_location=r.get("redirectlocation", None),
                    words=r.get("words", 0),
                    lines=r.get("lines", 0),
                    duration_ms=r.get("duration", None),
                )
                findings.append(finding)

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse ffuf JSON output: {e}")
            # Return empty list if parsing fails
            return []

        return findings

    def _store_results(
        self,
        target_url: str,
        findings: List[FfufFinding],
        raw_output: str
    ) -> None:
        """Store results in Nexus workspace."""
        timestamp = datetime.utcnow().isoformat()

        # Group findings by status code
        by_status = {}
        for f in findings:
            status = str(f.status_code)
            if status not in by_status:
                by_status[status] = []
            by_status[status].append(f.model_dump())

        # Store structured JSON results
        results_data = {
            "target_url": target_url,
            "findings": [f.model_dump() for f in findings],
            "count": len(findings),
            "by_status_code": by_status,
            "timestamp": timestamp,
            "scan_id": self.scan_id,
            "team_id": self.team_id,
            "tool": "ffuf",
        }

        results_json = json.dumps(results_data, indent=2)

        # Write results
        json_path = "/recon/ffuf/findings.json"
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
                raise FfufError(f"Failed to store results: {write_result.error}")

        # Store raw output for debugging
        raw_path = "/recon/ffuf/raw_output.json"
        write_result = self.backend.write(raw_path, raw_output)

        if write_result.error and "already exists" not in write_result.error:
            logger.warning(f"Failed to store raw output: {write_result.error}")

        logger.info(f"Stored ffuf results in Nexus workspace: {self.scan_id}")

    def cleanup(self) -> None:
        """Cleanup sandbox resources (only if we created it)."""
        if self.sandbox and self._owns_sandbox:
            try:
                self.sandbox.kill()
                logger.info("ffuf sandbox cleanup completed")
            except Exception as e:
                logger.warning(f"Sandbox cleanup failed: {e}")
