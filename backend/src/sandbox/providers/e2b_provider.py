"""
E2B Sandbox Provider.

This module implements sandboxed tool execution using E2B Cloud Sandboxes.
E2B provides secure, isolated execution environments with automatic cleanup.

Reference: https://e2b.dev/docs
"""

import asyncio
import logging
import time
from pathlib import Path
from typing import Dict, Optional

from e2b_code_interpreter import Sandbox

from src.sandbox.protocol import (
    SandboxExecutionError,
    SandboxExecutionResult,
    SandboxProvider,
    SandboxTimeoutError,
    ToolConfig,
)

logger = logging.getLogger(__name__)


class E2BSandboxProvider(SandboxProvider):
    """
    E2B cloud sandbox provider for secure tool execution.

    Features:
    - Cloud-based isolated environments
    - Automatic resource limits
    - Network isolation
    - Automatic cleanup
    - File system access for workspace

    Example:
        >>> provider = E2BSandboxProvider(api_key="e2b_...")
        >>> config = get_subfinder_config("example.com", "/workspace/subs.txt")
        >>> result = await provider.execute(config, "/tmp/scan-123", "scan-123")
        >>> print(result.stdout)
    """

    def __init__(self, api_key: str, template_id: Optional[str] = None):
        """
        Initialize E2B sandbox provider.

        Args:
            api_key: E2B API key from https://e2b.dev
            template_id: Custom template ID (e.g., 'threatweaver-security')
                        If None, uses default code-interpreter template
        """
        self.api_key = api_key
        self.template_id = template_id
        self._active_sandboxes: Dict[str, Sandbox] = {}

        # Set API key in environment for E2B SDK
        import os
        os.environ["E2B_API_KEY"] = api_key

    async def execute(
        self,
        tool_config: ToolConfig,
        workspace_dir: str,
        scan_id: str,
    ) -> SandboxExecutionResult:
        """
        Execute a security tool in an E2B sandbox.

        Args:
            tool_config: Tool configuration (image, command, limits)
            workspace_dir: Path to scan workspace (mounted read-write)
            scan_id: Unique scan identifier for isolation

        Returns:
            SandboxExecutionResult with stdout, stderr, exit code, output files

        Raises:
            SandboxTimeoutError: If execution exceeds timeout
            SandboxExecutionError: If execution fails
        """
        logger.info(
            f"Executing {tool_config.name} in E2B sandbox (scan: {scan_id})"
        )

        start_time = time.time()
        sandbox = None

        try:
            # Create sandbox (E2B SDK uses environment variable E2B_API_KEY)
            if self.template_id:
                # Use custom template with security tools
                sandbox = await asyncio.to_thread(
                    Sandbox.create,
                    template=self.template_id
                )
            else:
                # Use default code-interpreter template
                sandbox = await asyncio.to_thread(Sandbox.create)

            self._active_sandboxes[scan_id] = sandbox

            logger.info(f"E2B sandbox created: {sandbox.sandbox_id}")

            # Upload workspace files to sandbox
            workspace_path = Path(workspace_dir)
            if workspace_path.exists():
                await self._upload_workspace(sandbox, workspace_path)

            # Build command
            full_command = self._build_command(tool_config)

            logger.info(f"Executing command: {full_command}")

            # Execute command in sandbox with timeout
            try:
                execution = await asyncio.wait_for(
                    asyncio.to_thread(
                        sandbox.run_code,
                        full_command,
                    ),
                    timeout=tool_config.timeout,
                )
            except asyncio.TimeoutError:
                duration = time.time() - start_time
                logger.error(
                    f"{tool_config.name} timed out after {duration:.2f}s "
                    f"(limit: {tool_config.timeout}s)"
                )
                raise SandboxTimeoutError(
                    f"Execution exceeded timeout of {tool_config.timeout}s"
                )

            # Download output files from workspace
            output_files = await self._download_workspace(sandbox, workspace_path)

            duration = time.time() - start_time

            # Extract stdout/stderr from logs (not results)
            stdout = ""
            stderr = ""

            if hasattr(execution, "logs"):
                if hasattr(execution.logs, "stdout") and execution.logs.stdout:
                    stdout = "".join(execution.logs.stdout)
                if hasattr(execution.logs, "stderr") and execution.logs.stderr:
                    stderr = "".join(execution.logs.stderr)

            # Add error to stderr if present
            if execution.error:
                if stderr:
                    stderr += "\n"
                stderr += str(execution.error)

            # Parse exit code from stderr marker
            exit_code = 0
            if "__E2B_EXIT_CODE__=" in stderr:
                import re
                match = re.search(r"__E2B_EXIT_CODE__=(\d+)", stderr)
                if match:
                    exit_code = int(match.group(1))
                    # Remove the marker from stderr
                    stderr = re.sub(r"__E2B_EXIT_CODE__=\d+", "", stderr)

            # Determine success (no error AND exit code 0)
            success = execution.error is None and exit_code == 0

            logger.info(
                f"{tool_config.name} completed in {duration:.2f}s "
                f"(exit_code: {exit_code})"
            )

            return SandboxExecutionResult(
                success=success,
                exit_code=exit_code,
                stdout=stdout.strip(),
                stderr=stderr.strip(),
                duration=duration,
                output_files=output_files,
                error=str(execution.error) if execution.error else None,
            )

        except asyncio.TimeoutError:
            duration = time.time() - start_time
            logger.error(
                f"{tool_config.name} timed out after {duration:.2f}s "
                f"(limit: {tool_config.timeout}s)"
            )
            raise SandboxTimeoutError(
                f"Execution exceeded timeout of {tool_config.timeout}s"
            )

        except SandboxTimeoutError:
            # Re-raise timeout errors without wrapping
            raise

        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"{tool_config.name} failed after {duration:.2f}s: {e}",
                exc_info=True,
            )
            raise SandboxExecutionError(f"Execution failed: {e}")

        finally:
            # Cleanup sandbox
            if sandbox:
                try:
                    await asyncio.to_thread(sandbox.kill)
                    logger.info(f"E2B sandbox killed: {sandbox.sandbox_id}")
                except Exception as e:
                    logger.warning(f"Failed to kill sandbox: {e}")

                if scan_id in self._active_sandboxes:
                    del self._active_sandboxes[scan_id]

    async def cleanup(self, scan_id: str) -> None:
        """
        Clean up sandbox resources for a scan.

        Args:
            scan_id: Scan identifier to clean up
        """
        if scan_id in self._active_sandboxes:
            sandbox = self._active_sandboxes[scan_id]
            try:
                await asyncio.to_thread(sandbox.kill)
                logger.info(f"Cleaned up E2B sandbox for scan {scan_id}")
            except Exception as e:
                logger.warning(
                    f"Failed to cleanup sandbox for scan {scan_id}: {e}"
                )
            finally:
                del self._active_sandboxes[scan_id]

    async def health_check(self) -> bool:
        """
        Check if E2B sandbox provider is healthy.

        Returns:
            True if can create sandboxes, False otherwise
        """
        try:
            # Try to create a test sandbox
            if self.template_id:
                sandbox = await asyncio.to_thread(
                    Sandbox.create,
                    template=self.template_id
                )
            else:
                sandbox = await asyncio.to_thread(Sandbox.create)

            # Run simple Python command
            execution = await asyncio.to_thread(
                sandbox.run_code,
                "print('E2B health check OK')",
            )

            # Close sandbox
            await asyncio.to_thread(sandbox.kill)

            # Health check passes if no error
            return execution.error is None

        except Exception as e:
            logger.error(f"E2B health check failed: {e}")
            return False

    def _build_command(self, tool_config: ToolConfig) -> str:
        """
        Build Python code to execute shell command via subprocess.

        E2B Code Interpreter executes Python code, so we wrap shell commands
        in subprocess.run().

        Args:
            tool_config: Tool configuration

        Returns:
            Python code string that executes the shell command
        """
        # Build command args list
        cmd_parts = [tool_config.command] + tool_config.args

        # Create Python code that runs the command
        # Note: We DON'T use sys.exit() because E2B treats it as an error
        python_code = f'''
import subprocess
import sys

# Run command
result = subprocess.run(
    {cmd_parts!r},
    capture_output=True,
    text=True,
    timeout={tool_config.timeout}
)

# Print stdout and stderr
if result.stdout:
    print(result.stdout, end="")
if result.stderr:
    print(result.stderr, end="", file=sys.stderr)

# Print exit code on last line for parsing
print(f"__E2B_EXIT_CODE__={{result.returncode}}", file=sys.stderr)
'''

        return python_code

    async def _upload_workspace(
        self, sandbox: Sandbox, workspace_path: Path
    ) -> None:
        """
        Upload workspace files to sandbox.

        Args:
            sandbox: E2B sandbox instance
            workspace_path: Path to local workspace directory
        """
        # Create the workspace directory in sandbox
        await asyncio.to_thread(
            sandbox.run_code,
            """
import subprocess
subprocess.run(['mkdir', '-p', '/workspace'], check=True)
""",
        )

        logger.info("Workspace directory created in sandbox")

    async def _download_workspace(
        self, sandbox: Sandbox, workspace_path: Path
    ) -> Dict[str, str]:
        """
        Download output files from sandbox workspace.

        Args:
            sandbox: E2B sandbox instance
            workspace_path: Path to local workspace directory

        Returns:
            Dict mapping file paths to contents
        """
        output_files = {}

        try:
            # List files in workspace using Python
            list_code = """
import os
if os.path.exists('/workspace'):
    for f in os.listdir('/workspace'):
        if os.path.isfile(os.path.join('/workspace', f)):
            print(f)
"""
            execution = await asyncio.to_thread(
                sandbox.run_code,
                list_code,
            )

            # Extract filenames from logs.stdout
            filenames = []
            if hasattr(execution, "logs") and hasattr(execution.logs, "stdout"):
                stdout = "".join(execution.logs.stdout)
                filenames = [f.strip() for f in stdout.strip().split("\n") if f.strip()]

            # Read each file
            for filename in filenames:
                file_path = f"/workspace/{filename}"
                read_code = f"""
with open('{file_path}', 'r') as f:
    print(f.read(), end='')
"""
                execution = await asyncio.to_thread(
                    sandbox.run_code,
                    read_code,
                )

                if hasattr(execution, "logs") and hasattr(execution.logs, "stdout"):
                    content = "".join(execution.logs.stdout)
                    output_files[file_path] = content

                    # Also write to local workspace
                    local_file = workspace_path / filename
                    local_file.write_text(content)

                    logger.info(
                        f"Downloaded {file_path} ({len(content)} bytes)"
                    )

        except Exception as e:
            logger.warning(f"Failed to download workspace files: {e}")

        return output_files
