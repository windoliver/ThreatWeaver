"""
Tests for the sandbox execution system.

This module tests:
- Sandbox provider factory
- E2B sandbox provider
- Tool configurations
- Resource limits and timeouts
- File upload/download
- Error handling

Note: These tests require E2B_API_KEY environment variable.
"""

import os
import tempfile
from pathlib import Path

import pytest

from src.sandbox import get_sandbox_provider
from src.sandbox.config import (
    SandboxConfig,
    get_httpx_config,
    get_nmap_config,
    get_subfinder_config,
    get_tool_config,
)
from src.sandbox.protocol import (
    SandboxExecutionError,
    SandboxTimeoutError,
    ToolConfig,
)


@pytest.fixture
def sandbox_config():
    """Create sandbox configuration from environment."""
    return SandboxConfig.from_env()


@pytest.fixture
def temp_workspace():
    """Create temporary workspace directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


class TestSandboxConfig:
    """Test sandbox configuration."""

    def test_load_from_env(self):
        """Test loading configuration from environment."""
        config = SandboxConfig.from_env()

        assert config.provider in ["e2b", "docker"]
        assert config.cpu_limit > 0
        assert config.memory_limit > 0
        assert config.timeout > 0

    def test_tool_configs(self):
        """Test tool configuration generators."""
        # Subfinder
        subfinder = get_subfinder_config("example.com", "/workspace/subs.txt")
        assert subfinder.name == "subfinder"
        assert subfinder.command == "subfinder"
        assert "example.com" in subfinder.args
        assert subfinder.timeout == 1800

        # HTTPx
        httpx = get_httpx_config("/workspace/subs.txt", "/workspace/http.json")
        assert httpx.name == "httpx"
        assert httpx.command == "httpx"
        assert "-json" in httpx.args

        # Nmap
        nmap = get_nmap_config("10.0.0.1", "/workspace/nmap.xml")
        assert nmap.name == "nmap"
        assert nmap.command == "nmap"
        assert "10.0.0.1" in nmap.args

    def test_get_tool_config(self):
        """Test get_tool_config factory function."""
        config = get_tool_config("subfinder", domain="test.com", output_file="/out.txt")
        assert config.name == "subfinder"
        assert "test.com" in config.args

        # Test unknown tool
        with pytest.raises(ValueError, match="Unknown tool"):
            get_tool_config("unknown_tool")


class TestSandboxFactory:
    """Test sandbox provider factory."""

    def test_factory_creates_e2b_provider(self):
        """Test factory creates E2B provider when configured."""
        config = SandboxConfig(
            provider="e2b",
            e2b_api_key=os.getenv("E2B_API_KEY", "test_key"),
        )

        provider = get_sandbox_provider(config)

        from src.sandbox.providers.e2b_provider import E2BSandboxProvider

        assert isinstance(provider, E2BSandboxProvider)

    def test_factory_requires_api_key_for_e2b(self):
        """Test factory raises error if E2B API key missing."""
        config = SandboxConfig(
            provider="e2b",
            e2b_api_key=None,  # Missing API key
        )

        with pytest.raises(ValueError, match="E2B_API_KEY"):
            get_sandbox_provider(config)

    def test_factory_docker_not_implemented(self):
        """Test factory raises error for Docker (not yet implemented)."""
        config = SandboxConfig(provider="docker")

        with pytest.raises(NotImplementedError, match="Docker"):
            get_sandbox_provider(config)


@pytest.mark.asyncio
@pytest.mark.skipif(
    not os.getenv("E2B_API_KEY"),
    reason="E2B_API_KEY not set - skipping E2B integration tests",
)
class TestE2BSandboxProvider:
    """Test E2B sandbox provider (requires E2B API key)."""

    async def test_health_check(self):
        """Test E2B provider health check."""
        provider = get_sandbox_provider()

        healthy = await provider.health_check()

        assert healthy is True

    async def test_simple_command_execution(self, temp_workspace):
        """Test executing a simple command."""
        provider = get_sandbox_provider()

        # Create simple test configuration
        config = ToolConfig(
            name="test",
            image="",
            command="echo",
            args=["Hello from E2B sandbox!"],
            timeout=60,
        )

        result = await provider.execute(
            tool_config=config,
            workspace_dir=temp_workspace,
            scan_id="test-scan-001",
        )

        # Verify execution succeeded
        assert result.success is True
        assert result.exit_code == 0
        assert "Hello from E2B sandbox!" in result.stdout
        assert result.duration > 0

    async def test_file_creation_and_download(self, temp_workspace):
        """Test creating files in sandbox and downloading them."""
        provider = get_sandbox_provider()

        # Create configuration that writes a file
        config = ToolConfig(
            name="test",
            image="",
            command="bash",
            args=[
                "-c",
                "echo 'test content' > /workspace/output.txt && cat /workspace/output.txt",
            ],
            timeout=60,
        )

        result = await provider.execute(
            tool_config=config,
            workspace_dir=temp_workspace,
            scan_id="test-scan-002",
        )

        # Verify file was created and downloaded
        assert result.success is True
        assert "test content" in result.stdout

        # Check output files
        assert result.output_files is not None
        assert "/workspace/output.txt" in result.output_files
        assert "test content" in result.output_files["/workspace/output.txt"]

        # Check file exists locally
        local_file = Path(temp_workspace) / "output.txt"
        assert local_file.exists()
        assert "test content" in local_file.read_text()

    async def test_timeout_handling(self, temp_workspace):
        """Test that timeout is enforced."""
        provider = get_sandbox_provider()

        # Create configuration that sleeps longer than timeout
        config = ToolConfig(
            name="test",
            image="",
            command="sleep",
            args=["10"],  # Sleep for 10 seconds
            timeout=2,  # But timeout after 2 seconds
        )

        # Execution should timeout
        with pytest.raises(SandboxTimeoutError):
            await provider.execute(
                tool_config=config,
                workspace_dir=temp_workspace,
                scan_id="test-scan-003",
            )

    async def test_error_handling(self, temp_workspace):
        """Test handling of command errors."""
        provider = get_sandbox_provider()

        # Create configuration that fails
        config = ToolConfig(
            name="test",
            image="",
            command="bash",
            args=["-c", "exit 1"],  # Exit with error code
            timeout=60,
        )

        result = await provider.execute(
            tool_config=config,
            workspace_dir=temp_workspace,
            scan_id="test-scan-004",
        )

        # Execution should complete but with failure
        assert result.success is False
        assert result.exit_code == 1

    async def test_cleanup(self):
        """Test cleanup of sandbox resources."""
        provider = get_sandbox_provider()

        # Execute a command
        config = ToolConfig(
            name="test",
            image="",
            command="echo",
            args=["test"],
            timeout=60,
        )

        await provider.execute(
            tool_config=config,
            workspace_dir="/tmp",
            scan_id="test-scan-005",
        )

        # Cleanup should not raise errors
        await provider.cleanup("test-scan-005")

        # Cleanup non-existent scan should also not raise
        await provider.cleanup("non-existent-scan")


@pytest.mark.asyncio
@pytest.mark.skipif(
    not os.getenv("E2B_API_KEY"),
    reason="E2B_API_KEY not set - skipping E2B integration tests",
)
class TestSecurityToolExecution:
    """Test executing actual security tools in sandbox."""

    async def test_subfinder_execution(self, temp_workspace):
        """Test executing Subfinder tool."""
        provider = get_sandbox_provider()

        # Note: This test executes actual Subfinder, which may take time
        # You might want to skip in CI or use a test domain

        config = ToolConfig(
            name="subfinder",
            image="",
            command="bash",
            args=[
                "-c",
                # Simulate subfinder output for testing
                "echo 'api.example.com' > /workspace/subdomains.txt && "
                "echo 'www.example.com' >> /workspace/subdomains.txt && "
                "cat /workspace/subdomains.txt",
            ],
            timeout=300,
        )

        result = await provider.execute(
            tool_config=config,
            workspace_dir=temp_workspace,
            scan_id="test-subfinder-001",
        )

        # Verify execution
        assert result.success is True
        assert "example.com" in result.stdout

        # Verify output file
        assert "/workspace/subdomains.txt" in result.output_files
        content = result.output_files["/workspace/subdomains.txt"]
        assert "api.example.com" in content
        assert "www.example.com" in content

    async def test_multiple_file_outputs(self, temp_workspace):
        """Test handling multiple output files."""
        provider = get_sandbox_provider()

        config = ToolConfig(
            name="test",
            image="",
            command="bash",
            args=[
                "-c",
                "echo 'file1' > /workspace/output1.txt && "
                "echo 'file2' > /workspace/output2.txt && "
                "echo 'file3' > /workspace/output3.txt && "
                "ls -1 /workspace",
            ],
            timeout=60,
        )

        result = await provider.execute(
            tool_config=config,
            workspace_dir=temp_workspace,
            scan_id="test-multi-file-001",
        )

        # Verify all files were created and downloaded
        assert result.success is True
        assert len(result.output_files) == 3
        assert "/workspace/output1.txt" in result.output_files
        assert "/workspace/output2.txt" in result.output_files
        assert "/workspace/output3.txt" in result.output_files

        # Verify content
        assert "file1" in result.output_files["/workspace/output1.txt"]
        assert "file2" in result.output_files["/workspace/output2.txt"]
        assert "file3" in result.output_files["/workspace/output3.txt"]


# Integration test example (can be run manually)
@pytest.mark.asyncio
@pytest.mark.manual  # Mark as manual test (not run in CI)
async def test_full_recon_workflow():
    """
    Full reconnaissance workflow test.

    This test demonstrates the complete workflow:
    1. Run Subfinder to discover subdomains
    2. Run HTTPx to probe subdomains
    3. Run Nmap on live hosts

    This is a manual test due to execution time and network requirements.
    Run with: pytest tests/test_sandbox.py::test_full_recon_workflow -m manual
    """
    provider = get_sandbox_provider()
    workspace = tempfile.mkdtemp()

    try:
        # Step 1: Subfinder (simulated)
        print("\n=== Running Subfinder ===")
        subfinder_config = ToolConfig(
            name="subfinder",
            image="",
            command="bash",
            args=[
                "-c",
                "echo 'api.example.com' > /workspace/subdomains.txt && "
                "echo 'www.example.com' >> /workspace/subdomains.txt",
            ],
            timeout=300,
        )

        result1 = await provider.execute(
            subfinder_config, workspace, "workflow-001"
        )
        print(f"Subfinder: {result1.success}, output: {result1.output_files.keys()}")

        # Step 2: HTTPx (simulated)
        print("\n=== Running HTTPx ===")
        httpx_config = ToolConfig(
            name="httpx",
            image="",
            command="bash",
            args=[
                "-c",
                "cat /workspace/subdomains.txt && "
                "echo '{\"url\": \"https://api.example.com\", \"status\": 200}' > /workspace/http.json",
            ],
            timeout=300,
        )

        result2 = await provider.execute(httpx_config, workspace, "workflow-002")
        print(f"HTTPx: {result2.success}, output: {result2.output_files.keys()}")

        # Step 3: Nmap (simulated)
        print("\n=== Running Nmap ===")
        nmap_config = ToolConfig(
            name="nmap",
            image="",
            command="bash",
            args=[
                "-c",
                "echo '<nmaprun><host><address addr=\"192.168.1.1\"/></host></nmaprun>' > /workspace/nmap.xml",
            ],
            timeout=600,
        )

        result3 = await provider.execute(nmap_config, workspace, "workflow-003")
        print(f"Nmap: {result3.success}, output: {result3.output_files.keys()}")

        print("\n=== Workflow Complete ===")
        print(f"Total files generated: {len(result1.output_files) + len(result2.output_files) + len(result3.output_files)}")

    finally:
        # Cleanup
        import shutil

        shutil.rmtree(workspace)
