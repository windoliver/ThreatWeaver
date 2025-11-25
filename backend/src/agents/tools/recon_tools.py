"""
Recon Tools for DeepAgents.

These tools wrap our existing recon agents (Subfinder, HTTPx, Nmap, ffuf)
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

from agents.recon.subfinder_agent import SubfinderAgent
from agents.recon.httpx_agent import HTTPxAgent
from agents.recon.nmap_agent import NmapAgent, ScanProfile
from agents.recon.ffuf_agent import FfufAgent, WordlistType
from agents.backends.nexus_backend import NexusBackend
from config.nexus_config import get_nexus_fs

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
def run_subfinder(
    domain: str,
    config: RunnableConfig,  # LangGraph injects this automatically
    timeout: int = 300,
    filter_wildcards: bool = True,
) -> str:
    """
    Discover subdomains for a target domain using Subfinder.

    This tool runs Subfinder in an isolated E2B sandbox to discover
    subdomains via passive reconnaissance (DNS, search engines, etc.).

    Results are automatically stored in Nexus workspace at:
    /{team_id}/{thread_id}/recon/subfinder/subdomains.json

    Args:
        domain: Target domain to scan (e.g., "example.com")
        config: Runtime configuration (auto-injected by LangGraph)
        timeout: Execution timeout in seconds (default: 300)
        filter_wildcards: Remove wildcard DNS entries (default: True)

    Returns:
        JSON string with discovered subdomains and metadata

    Example:
        result = run_subfinder(domain="example.com")
        # Returns: '{"domain": "example.com", "subdomains": [...], "count": 25}'
    """
    # Extract thread_id and create backend
    scan_id, team_id, backend = _get_backend_from_config(config)

    try:
        # Create and execute Subfinder agent
        agent = SubfinderAgent(
            scan_id=scan_id,
            team_id=team_id,
            nexus_backend=backend
        )

        subdomains = agent.execute(
            domain=domain,
            timeout=timeout,
            filter_wildcards=filter_wildcards
        )

        agent.cleanup()

        # Return structured result
        result = {
            "success": True,
            "domain": domain,
            "subdomains": subdomains,
            "count": len(subdomains),
            "storage_path": "/recon/subfinder/subdomains.json"
        }

        logger.info(f"Subfinder found {len(subdomains)} subdomains for {domain}")
        return json.dumps(result, indent=2)

    except Exception as e:
        logger.error(f"Subfinder tool failed: {e}")
        return json.dumps({
            "success": False,
            "error": str(e),
            "domain": domain
        })


@tool
def run_httpx(
    targets: List[str],
    config: RunnableConfig,  # LangGraph injects this automatically
    timeout: int = 300,
    threads: int = 50,
    follow_redirects: bool = True,
    tech_detect: bool = True,
) -> str:
    """
    Probe targets for live HTTP/HTTPS services using HTTPx.

    This tool runs HTTPx in an isolated E2B sandbox to identify which
    discovered subdomains are actually responding to HTTP/HTTPS requests.

    Results are automatically stored in Nexus workspace at:
    /{team_id}/{thread_id}/recon/httpx/live_hosts.json

    Args:
        targets: List of domains/subdomains to probe
        config: Runtime configuration (auto-injected by LangGraph)
        timeout: Execution timeout in seconds (default: 300)
        threads: Number of concurrent threads (default: 50)
        follow_redirects: Follow HTTP redirects (default: True)
        tech_detect: Enable technology detection (default: True)

    Returns:
        JSON string with live host information and metadata

    Example:
        result = run_httpx(targets=["www.example.com", "api.example.com"])
        # Returns: '{"live_hosts_count": 2, "live_hosts": [...]}'
    """
    # Extract thread_id and create backend
    scan_id, team_id, backend = _get_backend_from_config(config)

    try:
        # Create and execute HTTPx agent
        agent = HTTPxAgent(
            scan_id=scan_id,
            team_id=team_id,
            nexus_backend=backend
        )

        live_hosts = agent.execute(
            targets=targets,
            timeout=timeout,
            threads=threads,
            follow_redirects=follow_redirects,
            tech_detect=tech_detect
        )

        agent.cleanup()

        # Return structured result
        result = {
            "success": True,
            "targets_count": len(targets),
            "live_hosts_count": len(live_hosts),
            "live_hosts": live_hosts,
            "storage_path": "/recon/httpx/live_hosts.json"
        }

        logger.info(f"HTTPx found {len(live_hosts)}/{len(targets)} live hosts")
        return json.dumps(result, indent=2)

    except Exception as e:
        logger.error(f"HTTPx tool failed: {e}")
        return json.dumps({
            "success": False,
            "error": str(e),
            "targets_count": len(targets)
        })


@tool
def run_nmap(
    targets: List[str],
    config: RunnableConfig,  # LangGraph injects this automatically
    profile: str = "default",
    ports: Optional[str] = None,
    timeout: int = 3600,
) -> str:
    """
    Scan targets for open ports and services using Nmap.

    This tool runs Nmap in an isolated E2B sandbox to discover open ports,
    running services, versions, and operating system information.

    Results are automatically stored in Nexus workspace at:
    /{team_id}/{thread_id}/recon/nmap/scan_results.json

    Args:
        targets: List of hosts/IPs to scan
        config: Runtime configuration (auto-injected by LangGraph)
        profile: Scan profile - "stealth", "default", or "aggressive" (default: "default")
        ports: Port specification (e.g., "22,80,443" or "1-1000"). None = top 1000
        timeout: Execution timeout in seconds (default: 3600, max: 3600)

    Returns:
        JSON string with scan results including open ports and services

    Example:
        result = run_nmap(targets=["192.168.1.1"], profile="default", ports="22,80,443")
        # Returns: '{"hosts_scanned": 1, "total_open_ports": 3, "hosts": [...]}'
    """
    # Extract thread_id and create backend
    scan_id, team_id, backend = _get_backend_from_config(config)

    try:
        # Map profile string to enum
        profile_map = {
            "stealth": ScanProfile.STEALTH,
            "default": ScanProfile.DEFAULT,
            "aggressive": ScanProfile.AGGRESSIVE
        }

        scan_profile = profile_map.get(profile.lower(), ScanProfile.DEFAULT)

        # Create and execute Nmap agent
        agent = NmapAgent(
            scan_id=scan_id,
            team_id=team_id,
            nexus_backend=backend
        )

        results = agent.execute(
            targets=targets,
            profile=scan_profile,
            ports=ports,
            timeout=timeout
        )

        agent.cleanup()

        # Return structured result
        result = {
            "success": True,
            "targets_count": len(targets),
            "hosts_scanned": len(results.get("hosts", [])),
            "total_open_ports": sum(len(h.get("ports", [])) for h in results.get("hosts", [])),
            "scan_profile": profile,
            "hosts": results.get("hosts", []),
            "scan_stats": results.get("scan_stats", {}),
            "storage_path": "/recon/nmap/scan_results.json"
        }

        logger.info(f"Nmap scanned {len(results.get('hosts', []))} hosts, found {result['total_open_ports']} open ports")
        return json.dumps(result, indent=2)

    except Exception as e:
        logger.error(f"Nmap tool failed: {e}")
        return json.dumps({
            "success": False,
            "error": str(e),
            "targets_count": len(targets)
        })


@tool
def run_ffuf(
    target_url: str,
    config: RunnableConfig,  # LangGraph injects this automatically
    wordlist: str = "common",
    extensions: Optional[List[str]] = None,
    threads: int = 40,
    rate_limit: int = 0,
    match_codes: Optional[List[int]] = None,
    filter_size: Optional[int] = None,
    timeout: int = 600,
) -> str:
    """
    Discover hidden directories and files on a target URL using ffuf.

    This tool runs ffuf (Fuzz Faster U Fool) in an isolated E2B sandbox to
    brute-force discover hidden paths, files, and endpoints on web applications.

    Results are automatically stored in Nexus workspace at:
    /{team_id}/{thread_id}/recon/ffuf/findings.json

    Args:
        target_url: Base URL to scan (e.g., "https://example.com")
        config: Runtime configuration (auto-injected by LangGraph)
        wordlist: Wordlist to use - "common", "dirb", "big", "raft-dirs" (default: "common")
        extensions: File extensions to append (e.g., [".php", ".bak", ".old"])
        threads: Number of concurrent threads (default: 40)
        rate_limit: Requests per second, 0 = unlimited (default: 0)
        match_codes: Only show these status codes (default: 200,204,301,302,307,401,403,405)
        filter_size: Hide responses of this exact size in bytes (default: None)
        timeout: Execution timeout in seconds (default: 600)

    Returns:
        JSON string with discovered paths and metadata

    Example:
        result = run_ffuf(
            target_url="https://example.com",
            wordlist="common",
            extensions=[".php", ".bak"]
        )
        # Returns: '{"count": 15, "findings": [{"path": "/admin", "status_code": 200}, ...]}'
    """
    # Extract thread_id and create backend
    scan_id, team_id, backend = _get_backend_from_config(config)

    try:
        # Map wordlist string to enum
        wordlist_map = {
            "common": WordlistType.COMMON,
            "dirb": WordlistType.DIRB_COMMON,
            "big": WordlistType.BIG,
            "raft-dirs": WordlistType.RAFT_DIRS,
        }
        wordlist_type = wordlist_map.get(wordlist.lower(), WordlistType.COMMON)

        # Create and execute ffuf agent
        agent = FfufAgent(
            scan_id=scan_id,
            team_id=team_id,
            nexus_backend=backend
        )

        findings = agent.execute(
            target_url=target_url,
            wordlist=wordlist_type,
            extensions=extensions,
            threads=threads,
            rate_limit=rate_limit,
            match_codes=match_codes,
            filter_size=filter_size,
            timeout=timeout,
        )

        agent.cleanup()

        # Group by status code for summary
        by_status = {}
        for f in findings:
            status = str(f.status_code)
            by_status[status] = by_status.get(status, 0) + 1

        # Return structured result
        result = {
            "success": True,
            "target_url": target_url,
            "count": len(findings),
            "by_status_code": by_status,
            "findings": [f.model_dump() for f in findings],
            "storage_path": "/recon/ffuf/findings.json"
        }

        logger.info(f"ffuf found {len(findings)} paths for {target_url}")
        return json.dumps(result, indent=2)

    except Exception as e:
        logger.error(f"ffuf tool failed: {e}")
        return json.dumps({
            "success": False,
            "error": str(e),
            "target_url": target_url
        })
