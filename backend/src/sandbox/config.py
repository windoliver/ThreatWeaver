"""
Sandbox configuration from environment variables.

This module loads sandbox settings from environment variables
and provides default configurations for security tools.
"""

import os
from dataclasses import dataclass
from typing import Dict

from src.sandbox.protocol import ToolConfig


@dataclass
class SandboxConfig:
    """
    Global sandbox configuration.

    Loaded from environment variables (.env file).
    """

    # Provider selection
    provider: str = "e2b"  # Options: e2b, docker
    e2b_api_key: str = None
    e2b_template_id: str = None  # Custom E2B template (optional)
    docker_host: str = "unix:///var/run/docker.sock"

    # Resource limits
    cpu_limit: float = 2.0  # CPU cores
    memory_limit: int = 4096  # MB
    timeout: int = 3600  # seconds (1 hour)
    network_limit: int = 10  # Mbps

    # Security settings
    read_only_filesystem: bool = True
    network_isolated: bool = True

    @classmethod
    def from_env(cls) -> "SandboxConfig":
        """Load configuration from environment variables."""
        return cls(
            provider=os.getenv("SANDBOX_PROVIDER", "e2b"),
            e2b_api_key=os.getenv("E2B_API_KEY"),
            e2b_template_id=os.getenv("E2B_TEMPLATE_ID"),
            docker_host=os.getenv("DOCKER_HOST", "unix:///var/run/docker.sock"),
            cpu_limit=float(os.getenv("SANDBOX_CPU_LIMIT", "2.0")),
            memory_limit=int(os.getenv("SANDBOX_MEMORY_LIMIT", "4096")),
            timeout=int(os.getenv("SANDBOX_TIMEOUT", "3600")),
            network_limit=int(os.getenv("SANDBOX_NETWORK_LIMIT", "10")),
        )


# Tool configurations
# These define how to run each security tool in a sandbox


def get_subfinder_config(domain: str, output_file: str) -> ToolConfig:
    """
    Get Subfinder tool configuration.

    Args:
        domain: Target domain to scan
        output_file: Path to write results (relative to workspace)

    Returns:
        ToolConfig for Subfinder execution
    """
    return ToolConfig(
        name="subfinder",
        image="projectdiscovery/subfinder:latest",
        command="subfinder",
        args=["-d", domain, "-o", output_file, "-silent"],
        timeout=1800,  # 30 minutes
        cpu_limit=1.0,
        memory_limit=1024,  # 1GB
    )


def get_httpx_config(input_file: str, output_file: str) -> ToolConfig:
    """
    Get HTTPx tool configuration.

    Args:
        input_file: Path to subdomain list (relative to workspace)
        output_file: Path to write results

    Returns:
        ToolConfig for HTTPx execution
    """
    return ToolConfig(
        name="httpx",
        image="projectdiscovery/httpx:latest",
        command="httpx",
        args=[
            "-l",
            input_file,
            "-o",
            output_file,
            "-json",
            "-silent",
            "-tech-detect",
            "-status-code",
        ],
        timeout=1800,  # 30 minutes
        cpu_limit=2.0,
        memory_limit=2048,  # 2GB
    )


def get_nmap_config(target: str, output_file: str) -> ToolConfig:
    """
    Get Nmap tool configuration.

    Args:
        target: Target IP/domain/CIDR to scan
        output_file: Path to write XML results

    Returns:
        ToolConfig for Nmap execution
    """
    return ToolConfig(
        name="nmap",
        image="instrumentisto/nmap:latest",
        command="nmap",
        args=[
            "-sV",  # Version detection
            "-sC",  # Default scripts
            "-T4",  # Aggressive timing
            "-oX",
            output_file,  # XML output
            "--max-retries",
            "2",
            "--host-timeout",
            "30m",
            target,
        ],
        timeout=3600,  # 1 hour
        cpu_limit=2.0,
        memory_limit=2048,
    )


def get_nuclei_config(target_file: str, output_file: str) -> ToolConfig:
    """
    Get Nuclei tool configuration.

    Args:
        target_file: Path to file with targets (relative to workspace)
        output_file: Path to write JSON results

    Returns:
        ToolConfig for Nuclei execution
    """
    return ToolConfig(
        name="nuclei",
        image="projectdiscovery/nuclei:latest",
        command="nuclei",
        args=[
            "-l",
            target_file,
            "-o",
            output_file,
            "-json",
            "-silent",
            "-severity",
            "critical,high,medium",
        ],
        timeout=3600,  # 1 hour
        cpu_limit=2.0,
        memory_limit=4096,  # 4GB (templates can be memory-intensive)
    )


def get_sqlmap_config(target_url: str, output_dir: str) -> ToolConfig:
    """
    Get SQLMap tool configuration.

    Args:
        target_url: Target URL with parameters to test
        output_dir: Directory to write results

    Returns:
        ToolConfig for SQLMap execution
    """
    return ToolConfig(
        name="sqlmap",
        image="pberba/sqlmap:latest",
        command="sqlmap",
        args=[
            "-u",
            target_url,
            "--batch",  # Non-interactive
            "--random-agent",
            "--output-dir",
            output_dir,
            "--dump",
            "--threads",
            "5",
        ],
        timeout=3600,  # 1 hour
        cpu_limit=2.0,
        memory_limit=2048,
        network_isolated=False,  # SQLMap needs network access
    )


# Registry of all tool configurations
TOOL_CONFIGS: Dict[str, callable] = {
    "subfinder": get_subfinder_config,
    "httpx": get_httpx_config,
    "nmap": get_nmap_config,
    "nuclei": get_nuclei_config,
    "sqlmap": get_sqlmap_config,
}


def get_tool_config(tool_name: str, **kwargs) -> ToolConfig:
    """
    Get configuration for a tool by name.

    Args:
        tool_name: Name of the tool (subfinder, httpx, nmap, nuclei, sqlmap)
        **kwargs: Tool-specific arguments

    Returns:
        ToolConfig for the tool

    Raises:
        ValueError: If tool_name is not recognized

    Example:
        >>> config = get_tool_config("subfinder", domain="example.com", output_file="/workspace/subs.txt")
        >>> config = get_tool_config("nmap", target="10.0.0.1", output_file="/workspace/nmap.xml")
    """
    if tool_name not in TOOL_CONFIGS:
        raise ValueError(
            f"Unknown tool: {tool_name}. "
            f"Available tools: {', '.join(TOOL_CONFIGS.keys())}"
        )

    return TOOL_CONFIGS[tool_name](**kwargs)
