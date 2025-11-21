"""
Demo: Sandbox Execution System

This example demonstrates secure tool execution using the sandbox system.

Usage:
    E2B_API_KEY=your_key python examples/sandbox_demo.py
"""

import asyncio
import os
import tempfile
from pathlib import Path

from src.sandbox import get_sandbox_provider
from src.sandbox.config import get_tool_config
from src.sandbox.protocol import ToolConfig


async def demo_simple_execution():
    """Demo 1: Execute a simple command in sandbox."""
    print("=" * 60)
    print("DEMO 1: Simple Command Execution")
    print("=" * 60)

    provider = get_sandbox_provider()

    # Simple echo command
    config = ToolConfig(
        name="test",
        image="",
        command="echo",
        args=["Hello from ThreatWeaver sandbox!"],
        timeout=60,
    )

    workspace = tempfile.mkdtemp()

    try:
        print(f"\n[SANDBOX] Executing: {config.command} {' '.join(config.args)}")

        result = await provider.execute(
            tool_config=config,
            workspace_dir=workspace,
            scan_id="demo-001",
        )

        print(f"\n[RESULT] Success: {result.success}")
        print(f"[RESULT] Exit Code: {result.exit_code}")
        print(f"[RESULT] Duration: {result.duration:.2f}s")
        print(f"[RESULT] Output: {result.stdout}")

    finally:
        # Cleanup
        import shutil

        shutil.rmtree(workspace)


async def demo_file_creation():
    """Demo 2: Create files in sandbox workspace."""
    print("\n" + "=" * 60)
    print("DEMO 2: File Creation and Download")
    print("=" * 60)

    provider = get_sandbox_provider()

    config = ToolConfig(
        name="test",
        image="",
        command="bash",
        args=[
            "-c",
            "echo 'Target 1' > /workspace/targets.txt && "
            "echo 'Target 2' >> /workspace/targets.txt && "
            "echo 'Target 3' >> /workspace/targets.txt && "
            "cat /workspace/targets.txt",
        ],
        timeout=60,
    )

    workspace = tempfile.mkdtemp()

    try:
        print(f"\n[SANDBOX] Creating files in /workspace")

        result = await provider.execute(
            tool_config=config,
            workspace_dir=workspace,
            scan_id="demo-002",
        )

        print(f"\n[RESULT] Success: {result.success}")
        print(f"[RESULT] Files created: {list(result.output_files.keys())}")

        if "/workspace/targets.txt" in result.output_files:
            content = result.output_files["/workspace/targets.txt"]
            print(f"\n[FILE CONTENT]")
            print(content)

            # Verify local file was downloaded
            local_file = Path(workspace) / "targets.txt"
            if local_file.exists():
                print(f"\n[LOCAL] File downloaded to: {local_file}")
                print(f"[LOCAL] Size: {local_file.stat().st_size} bytes")

    finally:
        import shutil

        shutil.rmtree(workspace)


async def demo_tool_configuration():
    """Demo 3: Use predefined tool configurations."""
    print("\n" + "=" * 60)
    print("DEMO 3: Tool Configuration (Simulated)")
    print("=" * 60)

    # Show available tool configurations
    print("\n[INFO] Available tool configurations:")
    print("  - subfinder: Subdomain discovery")
    print("  - httpx: HTTP probing")
    print("  - nmap: Port scanning")
    print("  - nuclei: Vulnerability scanning")
    print("  - sqlmap: SQL injection testing")

    # Example: Subfinder configuration
    subfinder_config = get_tool_config(
        "subfinder",
        domain="example.com",
        output_file="/workspace/subdomains.txt",
    )

    print(f"\n[CONFIG] Subfinder configuration:")
    print(f"  Name: {subfinder_config.name}")
    print(f"  Command: {subfinder_config.command}")
    print(f"  Args: {subfinder_config.args}")
    print(f"  CPU Limit: {subfinder_config.cpu_limit} cores")
    print(f"  Memory Limit: {subfinder_config.memory_limit} MB")
    print(f"  Timeout: {subfinder_config.timeout}s")

    # Simulate subfinder execution
    print(f"\n[SANDBOX] Simulating Subfinder execution...")

    provider = get_sandbox_provider()
    workspace = tempfile.mkdtemp()

    # Simulate subfinder output
    simulated_config = ToolConfig(
        name="subfinder",
        image="",
        command="bash",
        args=[
            "-c",
            "echo 'api.example.com' > /workspace/subdomains.txt && "
            "echo 'www.example.com' >> /workspace/subdomains.txt && "
            "echo 'admin.example.com' >> /workspace/subdomains.txt && "
            "cat /workspace/subdomains.txt",
        ],
        timeout=300,
    )

    try:
        result = await provider.execute(
            tool_config=simulated_config,
            workspace_dir=workspace,
            scan_id="demo-003",
        )

        if result.success:
            subdomains = result.output_files["/workspace/subdomains.txt"].splitlines()
            print(f"\n[RESULT] Discovered {len(subdomains)} subdomains:")
            for subdomain in subdomains:
                print(f"  - {subdomain}")

    finally:
        import shutil

        shutil.rmtree(workspace)


async def demo_error_handling():
    """Demo 4: Error handling and timeout."""
    print("\n" + "=" * 60)
    print("DEMO 4: Error Handling")
    print("=" * 60)

    provider = get_sandbox_provider()
    workspace = tempfile.mkdtemp()

    # Test 1: Command that fails
    print("\n[TEST 1] Command that fails (exit 1):")
    config_fail = ToolConfig(
        name="test",
        image="",
        command="bash",
        args=["-c", "echo 'This will fail' && exit 1"],
        timeout=60,
    )

    try:
        result = await provider.execute(
            tool_config=config_fail,
            workspace_dir=workspace,
            scan_id="demo-004-fail",
        )

        print(f"[RESULT] Success: {result.success}")
        print(f"[RESULT] Exit Code: {result.exit_code}")
        print(f"[RESULT] Output: {result.stdout}")

    except Exception as e:
        print(f"[ERROR] {e}")

    # Test 2: Timeout
    print("\n[TEST 2] Command that times out:")
    config_timeout = ToolConfig(
        name="test",
        image="",
        command="sleep",
        args=["10"],  # Sleep 10 seconds
        timeout=2,  # But timeout after 2 seconds
    )

    try:
        result = await provider.execute(
            tool_config=config_timeout,
            workspace_dir=workspace,
            scan_id="demo-004-timeout",
        )

        print(f"[RESULT] Success: {result.success}")

    except Exception as e:
        print(f"[ERROR] Timeout enforced: {type(e).__name__}")

    import shutil

    shutil.rmtree(workspace)


async def demo_health_check():
    """Demo 5: Health check."""
    print("\n" + "=" * 60)
    print("DEMO 5: Health Check")
    print("=" * 60)

    provider = get_sandbox_provider()

    print("\n[SANDBOX] Checking sandbox provider health...")

    healthy = await provider.health_check()

    if healthy:
        print("[RESULT] ✅ Sandbox provider is healthy!")
    else:
        print("[RESULT] ❌ Sandbox provider is not healthy")


async def main():
    """Run all demos."""
    print("\n" + "=" * 60)
    print("ThreatWeaver Sandbox System Demo")
    print("=" * 60)

    # Check for E2B API key
    if not os.getenv("E2B_API_KEY"):
        print("\n❌ ERROR: E2B_API_KEY environment variable not set")
        print("\nPlease set your E2B API key:")
        print("  export E2B_API_KEY=your_key_here")
        print("\nGet your key from: https://e2b.dev")
        return

    try:
        # Run all demos
        await demo_simple_execution()
        await demo_file_creation()
        await demo_tool_configuration()
        await demo_error_handling()
        await demo_health_check()

        print("\n" + "=" * 60)
        print("✅ All demos completed successfully!")
        print("=" * 60)

    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
