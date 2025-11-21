"""
Secure sandboxing layer for security tool execution.

This module provides isolated execution environments for security tools
(Nmap, Nuclei, Subfinder, HTTPx, SQLMap) using either E2B or Docker.

Architecture:
- SandboxProvider: Abstract base class defining sandbox interface
- E2BSandboxProvider: E2B cloud sandbox implementation (recommended)
- DockerSandboxProvider: Local Docker container implementation
- get_sandbox_provider(): Factory function to create appropriate provider

Security Features:
- Resource limits (CPU, memory, network, timeout)
- Filesystem isolation (read-only except /workspace)
- Network isolation (per-scan bridge networks)
- Automatic cleanup after execution

Reference: architecture.md - Infrastructure & Security Sandboxing
Issue: #23
"""

from src.sandbox.config import SandboxConfig
from src.sandbox.factory import get_sandbox_provider
from src.sandbox.protocol import (
    SandboxExecutionResult,
    SandboxProvider,
    ToolConfig,
)

__all__ = [
    "SandboxProvider",
    "SandboxExecutionResult",
    "ToolConfig",
    "SandboxConfig",
    "get_sandbox_provider",
]
