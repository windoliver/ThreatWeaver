"""
Nmap Agent - Network Scanning and Service Enumeration.

Uses Nmap tool in E2B sandbox to scan discovered hosts for open ports and services.
Supports multiple scan profiles (Stealth, Default, Aggressive) and parses XML output.

Reference:
- Issue #15: Implement Nmap Scanning Agent
- E2B Template ID: dbe6pq4es6hqj31ybd38 (threatweaver-security)
- Nmap: https://nmap.org/
"""

import json
import logging
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum

from e2b import Sandbox

from src.agents.backends.nexus_backend import NexusBackend

logger = logging.getLogger(__name__)


class ScanProfile(str, Enum):
    """Nmap scan profiles with different stealth/speed tradeoffs."""
    STEALTH = "stealth"      # Slow, evasive scans (-sS -T2 -f)
    DEFAULT = "default"      # Balanced scan (-sV -sC -T3)
    AGGRESSIVE = "aggressive"  # Fast, comprehensive (-A -T4)


class NmapError(Exception):
    """Exceptions raised by Nmap agent."""
    pass


class NmapAgent:
    """
    Network scanning agent using Nmap in E2B sandbox.

    This agent:
    1. Takes target hosts/IPs (from HTTPx or other sources)
    2. Runs Nmap in E2B sandbox with configurable scan profiles
    3. Parses XML output to structured JSON
    4. Identifies open ports, services, and versions
    5. Stores results in Nexus workspace

    Storage:
        /{team_id}/{scan_id}/recon/nmap/scan_results.json
        /{team_id}/{scan_id}/recon/nmap/scan_output.xml

    Example:
        >>> from src.config import get_nexus_fs
        >>> from src.agents.backends.nexus_backend import NexusBackend
        >>>
        >>> nx = get_nexus_fs()
        >>> backend = NexusBackend("scan-123", "team-abc", nx)
        >>>
        >>> agent = NmapAgent(
        ...     scan_id="scan-123",
        ...     team_id="team-abc",
        ...     nexus_backend=backend
        ... )
        >>> targets = ["45.33.32.156", "scanme.nmap.org"]
        >>> results = agent.execute(targets, profile=ScanProfile.DEFAULT)
        >>> print(f"Scanned {len(results['hosts'])} hosts")
    """

    def __init__(
        self,
        scan_id: str,
        team_id: str,
        nexus_backend: NexusBackend,
        sandbox: Optional[Sandbox] = None,
    ):
        """
        Initialize Nmap agent.

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
        profile: ScanProfile = ScanProfile.DEFAULT,
        ports: Optional[str] = None,
        timeout: int = 3600,
    ) -> Dict[str, Any]:
        """
        Scan targets for open ports and services.

        Args:
            targets: List of hosts/IPs to scan (e.g., ["192.168.1.1", "example.com"])
            profile: Scan profile (STEALTH, DEFAULT, or AGGRESSIVE)
            ports: Port specification (e.g., "22,80,443" or "1-1000"). None = top 1000
            timeout: Execution timeout in seconds (default: 1 hour, max: 1 hour)

        Returns:
            Dictionary with scan results including hosts, ports, services

        Raises:
            NmapError: If execution fails or times out

        Example:
            >>> results = agent.execute(
            ...     targets=["scanme.nmap.org"],
            ...     profile=ScanProfile.DEFAULT,
            ...     ports="22,80,443"
            ... )
            >>> for host in results['hosts']:
            ...     print(f"{host['ip']} has {len(host['ports'])} open ports")
        """
        logger.info(f"Starting Nmap scan for {len(targets)} targets (profile: {profile})")

        if not targets:
            logger.warning("No targets provided to Nmap agent")
            return {"hosts": [], "scan_stats": {}}

        # Enforce max timeout
        if timeout > 3600:
            logger.warning(f"Timeout {timeout}s exceeds max (3600s), capping at 3600s")
            timeout = 3600

        try:
            # Validate targets
            self._validate_targets(targets)

            # Create targets file in sandbox
            targets_content = "\n".join(targets)
            self.sandbox.files.write("/tmp/nmap_targets.txt", targets_content)

            # Run Nmap in E2B sandbox
            xml_output = self._run_nmap(
                profile=profile,
                ports=ports,
                timeout=timeout,
            )

            # Parse XML to JSON
            scan_results = self._parse_xml_output(xml_output)

            # Store results in Nexus workspace
            self._store_results(targets, scan_results, xml_output, profile)

            logger.info(
                f"Scanned {len(scan_results['hosts'])} hosts, "
                f"found {sum(len(h.get('ports', [])) for h in scan_results['hosts'])} open ports"
            )
            return scan_results

        except Exception as e:
            logger.error(f"Nmap execution failed: {e}")
            raise NmapError(f"Network scanning failed: {e}") from e

    def _run_nmap(
        self,
        profile: ScanProfile,
        ports: Optional[str],
        timeout: int,
    ) -> str:
        """Execute Nmap in E2B sandbox and return XML output."""
        # Build Nmap command based on profile
        nmap_args = self._build_nmap_command(profile, ports)

        command = f"nmap {nmap_args} -iL /tmp/nmap_targets.txt -oX /tmp/nmap_scan.xml"

        logger.debug(f"Running Nmap command: {command}")

        try:
            result = self.sandbox.commands.run(command, timeout=timeout)

            if result.exit_code != 0:
                # Nmap can return non-zero even on partial success
                # Only fail if there's clear error output
                if "ERROR" in result.stderr or "QUITTING" in result.stderr:
                    raise NmapError(
                        f"Nmap returned exit code {result.exit_code}: {result.stderr}"
                    )
                else:
                    logger.warning(f"Nmap non-zero exit ({result.exit_code}): {result.stderr}")

            # Read XML output
            xml_result = self.sandbox.commands.run("cat /tmp/nmap_scan.xml")
            if xml_result.exit_code != 0:
                raise NmapError("Failed to read Nmap XML output")

            return xml_result.stdout

        except TimeoutError as e:
            raise NmapError(f"Nmap scan timed out after {timeout}s") from e

    def _build_nmap_command(self, profile: ScanProfile, ports: Optional[str]) -> str:
        """Build Nmap command arguments based on scan profile."""
        args = []

        # Profile-specific arguments
        if profile == ScanProfile.STEALTH:
            # Stealth: TCP connect scan (no root needed), slow timing
            # Note: Can't use -sS (SYN scan) in unprivileged E2B sandbox
            args.extend(["-sT", "-T2", "--randomize-hosts"])
        elif profile == ScanProfile.DEFAULT:
            # Default: Version detection, default scripts, normal timing
            # Use -sT instead of default -sS for unprivileged scanning
            args.extend(["-sT", "-sV", "-sC", "-T3"])
        elif profile == ScanProfile.AGGRESSIVE:
            # Aggressive: Version, scripts, fast timing
            # Note: Can't use -O (OS detection) without root in sandbox
            args.extend(["-sT", "-sV", "-sC", "-T4", "--script=default"])

        # Port specification
        if ports:
            args.append(f"-p {ports}")
        # else: use Nmap default (top 1000 ports)

        # Add -Pn to skip host discovery (works better in sandbox)
        args.append("-Pn")

        return " ".join(args)

    def _validate_targets(self, targets: List[str]) -> None:
        """Validate target list."""
        if not isinstance(targets, list):
            raise ValueError("Targets must be a list")

        if len(targets) == 0:
            raise ValueError("Targets list cannot be empty")

        for target in targets:
            if not target or not isinstance(target, str):
                raise ValueError(f"Invalid target: {target}")

            # Basic validation - allow IPs, hostnames, CIDR
            if len(target) > 253:
                raise ValueError(f"Target too long: {target}")

    def _parse_xml_output(self, xml_string: str) -> Dict[str, Any]:
        """
        Parse Nmap XML output into structured JSON.

        Returns a dictionary with:
        - hosts: List of scanned hosts with ports and services
        - scan_stats: Scan statistics (start time, end time, elapsed)
        """
        try:
            root = ET.fromstring(xml_string)
        except ET.ParseError as e:
            raise NmapError(f"Failed to parse Nmap XML: {e}")

        hosts = []

        # Parse each host
        for host_elem in root.findall("host"):
            # Get host status
            status = host_elem.find("status")
            if status is None or status.get("state") != "up":
                continue  # Skip down hosts

            # Get IP address
            address_elem = host_elem.find("address[@addrtype='ipv4']")
            if address_elem is None:
                address_elem = host_elem.find("address[@addrtype='ipv6']")

            ip = address_elem.get("addr") if address_elem is not None else "unknown"

            # Get hostname
            hostnames = []
            hostnames_elem = host_elem.find("hostnames")
            if hostnames_elem is not None:
                for hostname_elem in hostnames_elem.findall("hostname"):
                    name = hostname_elem.get("name")
                    if name:
                        hostnames.append(name)

            # Parse ports
            ports = []
            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    state_elem = port_elem.find("state")
                    if state_elem is None or state_elem.get("state") != "open":
                        continue  # Only include open ports

                    service_elem = port_elem.find("service")

                    port_data = {
                        "port": int(port_elem.get("portid", 0)),
                        "protocol": port_elem.get("protocol", "tcp"),
                        "state": state_elem.get("state", "unknown"),
                        "service": service_elem.get("name", "unknown") if service_elem is not None else "unknown",
                        "product": service_elem.get("product", "") if service_elem is not None else "",
                        "version": service_elem.get("version", "") if service_elem is not None else "",
                        "extrainfo": service_elem.get("extrainfo", "") if service_elem is not None else "",
                    }

                    ports.append(port_data)

            # Get OS detection if available
            os_matches = []
            os_elem = host_elem.find("os")
            if os_elem is not None:
                for osmatch_elem in os_elem.findall("osmatch"):
                    os_matches.append({
                        "name": osmatch_elem.get("name", ""),
                        "accuracy": int(osmatch_elem.get("accuracy", 0)),
                    })

            host_data = {
                "ip": ip,
                "hostnames": hostnames,
                "state": status.get("state") if status is not None else "unknown",
                "ports": ports,
                "os_matches": os_matches,
            }

            hosts.append(host_data)

        # Parse scan statistics
        runstats = root.find("runstats")
        scan_stats = {}

        if runstats is not None:
            finished = runstats.find("finished")
            if finished is not None:
                scan_stats = {
                    "start_time": root.get("start", ""),
                    "end_time": finished.get("time", ""),
                    "elapsed": finished.get("elapsed", ""),
                    "summary": finished.get("summary", ""),
                }

        return {
            "hosts": hosts,
            "scan_stats": scan_stats,
        }

    def _store_results(
        self,
        targets: List[str],
        scan_results: Dict[str, Any],
        xml_output: str,
        profile: ScanProfile,
    ) -> None:
        """Store results in Nexus workspace."""
        timestamp = datetime.now().isoformat()

        # Store structured JSON results
        results_data = {
            "targets_count": len(targets),
            "hosts_scanned": len(scan_results["hosts"]),
            "total_open_ports": sum(len(h.get("ports", [])) for h in scan_results["hosts"]),
            "scan_profile": profile.value,
            "hosts": scan_results["hosts"],
            "scan_stats": scan_results["scan_stats"],
            "timestamp": timestamp,
            "scan_id": self.scan_id,
            "team_id": self.team_id,
            "tool": "nmap",
            "version": "7.95"
        }

        results_json = json.dumps(results_data, indent=2)

        # Write JSON results
        json_path = "/recon/nmap/scan_results.json"
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
                        raise NmapError(f"Failed to update results: {edit_result.error}")
                else:
                    logger.error(f"Failed to read existing results")
                    raise NmapError(f"Failed to read existing results")
            else:
                logger.error(f"Failed to store results: {write_result.error}")
                raise NmapError(f"Failed to store results: {write_result.error}")

        # Store raw XML output
        xml_path = "/recon/nmap/scan_output.xml"
        write_result = self.backend.write(xml_path, xml_output)

        if write_result.error:
            if "already exists" in write_result.error:
                old_content = self.backend.read(xml_path)
                if old_content and not old_content.startswith("Error:"):
                    old_lines = [line.split("→", 1)[1] if "→" in line else line
                                for line in old_content.split("\n")]
                    old_content_clean = "\n".join(old_lines)

                    self.backend.edit(xml_path, old_content_clean, xml_output)
            else:
                logger.warning(f"Failed to store XML output: {write_result.error}")

        logger.info(f"Stored results in Nexus workspace: {self.scan_id}")

    def cleanup(self) -> None:
        """Cleanup sandbox resources (only if we created it)."""
        if self.sandbox and self._owns_sandbox:
            try:
                self.sandbox.kill()
                logger.info("Sandbox cleanup completed")
            except Exception as e:
                logger.warning(f"Sandbox cleanup failed: {e}")
