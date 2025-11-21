"""
Sandbox provider protocol and data structures.

This module defines the abstract interface for sandbox providers
and data structures for tool configurations and execution results.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class ToolConfig:
    """
    Configuration for a security tool.

    Attributes:
        name: Tool name (e.g., "subfinder", "nmap")
        image: Docker image or E2B template
        command: Command to execute
        args: List of command arguments
        env: Environment variables
        timeout: Execution timeout in seconds
        cpu_limit: CPU cores (e.g., 2.0)
        memory_limit: Memory limit in MB
        network_isolated: Whether to isolate network
    """

    name: str
    image: str
    command: str
    args: List[str]
    env: Dict[str, str] = None
    timeout: int = 3600  # 1 hour default
    cpu_limit: float = 2.0
    memory_limit: int = 4096  # 4GB
    network_isolated: bool = True


@dataclass
class SandboxExecutionResult:
    """
    Result of a sandboxed tool execution.

    Attributes:
        success: Whether execution completed successfully
        exit_code: Process exit code
        stdout: Standard output
        stderr: Standard error
        duration: Execution duration in seconds
        output_files: Dict mapping file paths to contents
        error: Error message if execution failed
    """

    success: bool
    exit_code: int
    stdout: str
    stderr: str
    duration: float
    output_files: Dict[str, str] = None
    error: Optional[str] = None


class SandboxProvider(ABC):
    """
    Abstract base class for sandbox providers.

    Implementations:
    - E2BSandboxProvider: Cloud sandbox using E2B
    - DockerSandboxProvider: Local Docker containers
    """

    @abstractmethod
    async def execute(
        self,
        tool_config: ToolConfig,
        workspace_dir: str,
        scan_id: str,
    ) -> SandboxExecutionResult:
        """
        Execute a security tool in an isolated sandbox.

        Args:
            tool_config: Tool configuration (image, command, limits)
            workspace_dir: Path to scan workspace (mounted read-write)
            scan_id: Unique scan identifier for isolation

        Returns:
            SandboxExecutionResult with stdout, stderr, exit code, output files

        Raises:
            SandboxTimeoutError: If execution exceeds timeout
            SandboxResourceError: If resource limits exceeded
            SandboxExecutionError: If execution fails

        Example:
            >>> provider = get_sandbox_provider()
            >>> config = ToolConfig(
            ...     name="subfinder",
            ...     image="projectdiscovery/subfinder:latest",
            ...     command="subfinder",
            ...     args=["-d", "example.com", "-o", "/workspace/subdomains.txt"],
            ... )
            >>> result = await provider.execute(
            ...     config, workspace_dir="/tmp/scan-123", scan_id="scan-123"
            ... )
            >>> print(result.stdout)
            >>> print(result.output_files["/workspace/subdomains.txt"])
        """
        pass

    @abstractmethod
    async def cleanup(self, scan_id: str) -> None:
        """
        Clean up sandbox resources for a scan.

        Args:
            scan_id: Scan identifier to clean up

        This should:
        - Stop running containers
        - Remove networks
        - Delete temporary files
        - Free allocated resources
        """
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """
        Check if sandbox provider is healthy and ready.

        Returns:
            True if healthy, False otherwise
        """
        pass


class SandboxTimeoutError(Exception):
    """Raised when sandbox execution exceeds timeout."""

    pass


class SandboxResourceError(Exception):
    """Raised when sandbox resource limits are exceeded."""

    pass


class SandboxExecutionError(Exception):
    """Raised when sandbox execution fails."""

    pass
