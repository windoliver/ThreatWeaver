#!/usr/bin/env python3
"""
ThreatWeaver Sandbox Demo Script
Interactive demonstration of the E2B sandbox system
"""

import asyncio
import os
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.sandbox.factory import get_sandbox_provider
from src.sandbox.config import (
    get_subfinder_config,
    get_httpx_config,
    get_nmap_config,
)
from src.sandbox.protocol import SandboxTimeoutError, SandboxExecutionError


def print_header(text: str):
    """Print a section header."""
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70 + "\n")


def print_result(result):
    """Print execution result."""
    status = "✅ SUCCESS" if result.success else "❌ FAILED"
    print(f"\n{status}")
    print(f"Duration: {result.duration:.2f}s")
    print(f"Exit Code: {result.exit_code}")

    if result.stdout:
        print(f"\n--- STDOUT ---")
        print(result.stdout[:500])  # Limit output
        if len(result.stdout) > 500:
            print(f"... ({len(result.stdout) - 500} more characters)")

    if result.stderr:
        print(f"\n--- STDERR ---")
        print(result.stderr[:500])
        if len(result.stderr) > 500:
            print(f"... ({len(result.stderr) - 500} more characters)")

    if result.output_files:
        print(f"\n--- OUTPUT FILES ---")
        for path, content in result.output_files.items():
            print(f"  {path}: {len(content)} bytes")

    if result.error:
        print(f"\n--- ERROR ---")
        print(result.error)


async def demo_simple_command():
    """Demo 1: Simple echo command."""
    print_header("Demo 1: Simple Command Execution")

    print("Executing: echo 'Hello from ThreatWeaver Sandbox!'")

    provider = get_sandbox_provider()

    # Create local workspace directory
    workspace = Path("/tmp/demo-simple")
    workspace.mkdir(parents=True, exist_ok=True)

    from src.sandbox.protocol import ToolConfig
    config = ToolConfig(
        name="echo-test",
        image="",
        command="echo",
        args=["Hello from ThreatWeaver Sandbox!"],
        timeout=30,
    )

    try:
        result = await provider.execute(
            tool_config=config,
            workspace_dir=str(workspace),
            scan_id="demo-simple-001",
        )
        print_result(result)
    except Exception as e:
        print(f"❌ Error: {e}")


async def demo_file_operations():
    """Demo 2: File creation and download."""
    print_header("Demo 2: File Operations")

    print("Creating files in /workspace and downloading them...")

    provider = get_sandbox_provider()

    # Create local workspace directory
    workspace = Path("/tmp/demo-files")
    workspace.mkdir(parents=True, exist_ok=True)

    from src.sandbox.protocol import ToolConfig
    config = ToolConfig(
        name="file-test",
        image="",
        command="bash",
        args=[
            "-c",
            "mkdir -p /workspace && "
            "echo 'ThreatWeaver Test Output' > /workspace/test.txt && "
            "echo 'Line 1' > /workspace/data.log && "
            "echo 'Line 2' >> /workspace/data.log && "
            "cat /workspace/test.txt"
        ],
        timeout=30,
    )

    try:
        result = await provider.execute(
            tool_config=config,
            workspace_dir=str(workspace),
            scan_id="demo-files-001",
        )
        print_result(result)

        # Check local files
        workspace = Path("/tmp/demo-files")
        if workspace.exists():
            print(f"\n--- LOCAL WORKSPACE: {workspace} ---")
            for file in workspace.iterdir():
                if file.is_file():
                    print(f"  {file.name}: {file.stat().st_size} bytes")
                    content = file.read_text()
                    print(f"    Content: {content[:100]}")
    except Exception as e:
        print(f"❌ Error: {e}")


async def demo_security_tool():
    """Demo 3: Simulated security tool workflow."""
    print_header("Demo 3: Simulated Security Tool Workflow")

    print("Simulating a reconnaissance workflow...")
    print("(In production, this would run actual tools like Subfinder, HTTPx, Nmap)")

    provider = get_sandbox_provider()

    # Create local workspace directory
    workspace = Path("/tmp/demo-recon")
    workspace.mkdir(parents=True, exist_ok=True)

    from src.sandbox.protocol import ToolConfig

    # Simulate a reconnaissance script that:
    # 1. Discovers targets
    # 2. Performs checks
    # 3. Saves results to files
    config = ToolConfig(
        name="recon-simulation",
        image="",
        command="bash",
        args=[
            "-c",
            "mkdir -p /workspace && "
            "echo 'Simulating subdomain discovery...' && "
            "echo 'www.example.com' > /workspace/subdomains.txt && "
            "echo 'api.example.com' >> /workspace/subdomains.txt && "
            "echo 'mail.example.com' >> /workspace/subdomains.txt && "
            "echo '' && "
            "echo 'Found 3 subdomains:' && "
            "cat /workspace/subdomains.txt && "
            "echo '' && "
            "echo 'Simulating port scan...' && "
            "echo '80 (HTTP)' > /workspace/ports.txt && "
            "echo '443 (HTTPS)' >> /workspace/ports.txt && "
            "echo '22 (SSH)' >> /workspace/ports.txt && "
            "echo 'Found 3 open ports' && "
            "echo '' && "
            "echo '✅ Reconnaissance complete!'"
        ],
        timeout=30,
    )

    try:
        result = await provider.execute(
            tool_config=config,
            workspace_dir=str(workspace),
            scan_id="demo-recon-001",
        )
        print_result(result)

        # Show discovered data
        workspace = Path("/tmp/demo-recon")

        print("\n📊 Downloaded Files:")

        subdomain_file = workspace / "subdomains.txt"
        if subdomain_file.exists():
            subdomains = subdomain_file.read_text().strip().split("\n")
            print(f"\n  subdomains.txt ({len(subdomains)} entries):")
            for subdomain in subdomains:
                print(f"    - {subdomain}")

        ports_file = workspace / "ports.txt"
        if ports_file.exists():
            ports = ports_file.read_text().strip().split("\n")
            print(f"\n  ports.txt ({len(ports)} entries):")
            for port in ports:
                print(f"    - {port}")

        print("\n💡 In production, these would be real results from:")
        print("   - Subfinder (subdomain discovery)")
        print("   - Nmap (port scanning)")
        print("   - HTTPx (HTTP probing)")
        print("   - Nuclei (vulnerability scanning)")

    except Exception as e:
        print(f"❌ Error: {e}")


async def demo_timeout_handling():
    """Demo 4: Timeout enforcement."""
    print_header("Demo 4: Timeout Enforcement")

    print("Running a command that sleeps for 10s with 2s timeout...")
    print("Expected: Timeout error after 2 seconds")

    provider = get_sandbox_provider()

    # Create local workspace directory
    workspace = Path("/tmp/demo-timeout")
    workspace.mkdir(parents=True, exist_ok=True)

    from src.sandbox.protocol import ToolConfig
    config = ToolConfig(
        name="timeout-test",
        image="",
        command="sleep",
        args=["10"],
        timeout=2,
    )

    try:
        result = await provider.execute(
            tool_config=config,
            workspace_dir=str(workspace),
            scan_id="demo-timeout-001",
        )
        print_result(result)
        print("⚠️ WARNING: Should have timed out!")
    except SandboxTimeoutError as e:
        print(f"✅ Timeout enforced correctly!")
        print(f"   Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")


async def demo_error_handling():
    """Demo 5: Error handling."""
    print_header("Demo 5: Error Handling")

    print("Running a command that exits with error code 1...")

    provider = get_sandbox_provider()

    # Create local workspace directory
    workspace = Path("/tmp/demo-error")
    workspace.mkdir(parents=True, exist_ok=True)

    from src.sandbox.protocol import ToolConfig
    config = ToolConfig(
        name="error-test",
        image="",
        command="bash",
        args=["-c", "echo 'This will fail' && exit 1"],
        timeout=30,
    )

    try:
        result = await provider.execute(
            tool_config=config,
            workspace_dir=str(workspace),
            scan_id="demo-error-001",
        )
        print_result(result)

        if not result.success:
            print("\n✅ Error handled correctly (success=False, exit_code=1)")
    except Exception as e:
        print(f"❌ Error: {e}")


async def demo_health_check():
    """Demo 6: Provider health check."""
    print_header("Demo 6: Provider Health Check")

    print("Checking if E2B sandbox provider is healthy...")

    provider = get_sandbox_provider()

    try:
        healthy = await provider.health_check()

        if healthy:
            print("✅ Provider is healthy!")
            print("   - Can create sandboxes")
            print("   - Can execute Python code")
            print("   - Can cleanup resources")
        else:
            print("❌ Provider is unhealthy")
    except Exception as e:
        print(f"❌ Health check failed: {e}")


async def run_all_demos():
    """Run all demonstrations."""
    print("\n" + "█" * 70)
    print("█" + " " * 68 + "█")
    print("█" + "  ThreatWeaver Sandbox System - Interactive Demo".center(68) + "█")
    print("█" + " " * 68 + "█")
    print("█" * 70)

    # Check E2B API key
    api_key = os.environ.get("E2B_API_KEY")
    if not api_key:
        print("\n❌ ERROR: E2B_API_KEY not set")
        print("\nPlease set your E2B API key:")
        print("  export E2B_API_KEY=e2b_9b7c601537c06efcc44aad5c13fb19fd2d257476")
        print("\nThen run this script again:")
        print("  python run_sandbox_demo.py")
        sys.exit(1)

    print(f"\n✅ E2B API Key: {api_key[:10]}...{api_key[-4:]}")
    print(f"✅ Sandbox Provider: E2B Cloud Sandboxes")

    demos = [
        ("1", "Simple Command", demo_simple_command),
        ("2", "File Operations", demo_file_operations),
        ("3", "Security Tool Workflow", demo_security_tool),
        ("4", "Timeout Handling", demo_timeout_handling),
        ("5", "Error Handling", demo_error_handling),
        ("6", "Health Check", demo_health_check),
    ]

    print("\n" + "─" * 70)
    print("Available Demos:")
    for num, name, _ in demos:
        print(f"  [{num}] {name}")
    print("  [A] Run all demos")
    print("  [Q] Quit")
    print("─" * 70)

    choice = input("\nSelect demo (1-6, A for all, Q to quit): ").strip().upper()

    if choice == "Q":
        print("\nGoodbye! 👋")
        return

    if choice == "A":
        # Run all demos
        for num, name, demo_func in demos:
            await demo_func()
            print("\n" + "─" * 70)
    else:
        # Run selected demo
        for num, name, demo_func in demos:
            if choice == num:
                await demo_func()
                break
        else:
            print(f"\n❌ Invalid choice: {choice}")
            return

    print_header("Demo Complete!")
    print("✅ All demonstrations completed successfully")
    print("\nNext steps:")
    print("  1. Check the test suite: E2B_API_KEY=... pytest tests/test_sandbox.py -v")
    print("  2. Review documentation: docs/SANDBOX_SYSTEM.md")
    print("  3. Integrate into your agents!")


if __name__ == "__main__":
    try:
        asyncio.run(run_all_demos())
    except KeyboardInterrupt:
        print("\n\n⚠️ Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
