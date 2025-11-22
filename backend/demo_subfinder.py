#!/usr/bin/env python3
"""
Subfinder Agent Demo Script

Run subdomain discovery against a target domain using E2B sandbox.

Usage:
    python demo_subfinder.py example.com
    python demo_subfinder.py --domain hackerone.com --timeout 120
"""

import argparse
import json
import os
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from e2b import Sandbox
from src.agents.recon.subfinder_agent import SubfinderAgent
from src.agents.backends.nexus_backend import NexusBackend
from src.config import get_nexus_fs


def main():
    parser = argparse.ArgumentParser(
        description="Run Subfinder agent to discover subdomains"
    )
    parser.add_argument(
        "domain",
        nargs="?",
        default="google.com",
        help="Target domain (default: google.com)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Timeout in seconds (default: 300)"
    )
    parser.add_argument(
        "--no-wildcards",
        action="store_true",
        help="Filter out wildcard DNS entries"
    )
    parser.add_argument(
        "--scan-id",
        default="demo-scan",
        help="Scan ID (default: demo-scan)"
    )
    parser.add_argument(
        "--team-id",
        default="demo-team",
        help="Team ID (default: demo-team)"
    )

    args = parser.parse_args()

    # Check E2B API key
    if not os.getenv("E2B_API_KEY"):
        print("❌ Error: E2B_API_KEY environment variable not set")
        print("\nSet it with:")
        print("  export E2B_API_KEY=your_key_here")
        print("\nOr run with:")
        print(f"  E2B_API_KEY=your_key python {sys.argv[0]} {args.domain}")
        sys.exit(1)

    print("🔍 ThreatWeaver - Subfinder Agent Demo")
    print("=" * 60)
    print(f"Target Domain: {args.domain}")
    print(f"Timeout: {args.timeout}s")
    print(f"Filter Wildcards: {not args.no_wildcards}")
    print(f"Scan ID: {args.scan_id}")
    print(f"Team ID: {args.team_id}")
    print("=" * 60)

    # Initialize Nexus workspace
    print("\n📁 Initializing Nexus workspace...")
    nx = get_nexus_fs()
    backend = NexusBackend(
        scan_id=args.scan_id,
        team_id=args.team_id,
        nexus_fs=nx
    )
    print(f"✅ Workspace: {args.team_id}/{args.scan_id}/")

    # Create E2B sandbox
    print("\n🐳 Creating E2B sandbox with security tools...")
    try:
        sandbox = Sandbox.create(template="dbe6pq4es6hqj31ybd38")
        print(f"✅ Sandbox created: {sandbox.sandbox_id}")
    except Exception as e:
        print(f"❌ Failed to create sandbox: {e}")
        print("\nTroubleshooting:")
        print("1. Check E2B API key is valid")
        print("2. Template 'dbe6pq4es6hqj31ybd38' should be public")
        sys.exit(1)

    # Create Subfinder agent
    print("\n🤖 Initializing Subfinder agent...")
    agent = SubfinderAgent(
        scan_id=args.scan_id,
        team_id=args.team_id,
        nexus_backend=backend,
        sandbox=sandbox
    )
    print("✅ Agent ready")

    # Run subdomain discovery
    print(f"\n🔎 Running subdomain discovery for {args.domain}...")
    print(f"⏱️  This may take up to {args.timeout} seconds...\n")

    try:
        subdomains = agent.execute(
            domain=args.domain,
            timeout=args.timeout,
            filter_wildcards=not args.no_wildcards
        )

        print("\n" + "=" * 60)
        print(f"✅ Discovery complete! Found {len(subdomains)} subdomains")
        print("=" * 60)

        # Show first 10 results
        print("\n📋 Sample Results (first 10):")
        for i, subdomain in enumerate(subdomains[:10], 1):
            print(f"  {i:2d}. {subdomain}")

        if len(subdomains) > 10:
            print(f"\n  ... and {len(subdomains) - 10} more")

        # Show storage location
        print("\n💾 Results stored in Nexus:")
        print(f"  - JSON: /{args.team_id}/{args.scan_id}/recon/subfinder/subdomains.json")
        print(f"  - Raw:  /{args.team_id}/{args.scan_id}/recon/subfinder/raw_output.txt")

        # Read and display JSON results (read all lines, not just first 2000)
        json_path = "/recon/subfinder/subdomains.json"
        json_content = backend.read(json_path, limit=999999)

        if json_content and not json_content.startswith("Error:"):
            # Strip line numbers and parse JSON
            # Format is "     1→{" where the arrow separates line number from content
            lines = []
            for line in json_content.split("\n"):
                if "→" in line:
                    # Split on first arrow and take content after it
                    _, content = line.split("→", 1)
                    lines.append(content)
                else:
                    # No line number, keep as-is
                    lines.append(line)

            json_str = "\n".join(lines)

            try:
                data = json.loads(json_str)
                print("\n📊 Scan Metadata:")
                print(f"  - Scan ID: {data['scan_id']}")
                print(f"  - Team ID: {data['team_id']}")
                print(f"  - Timestamp: {data['timestamp']}")
                print(f"  - Tool: {data['tool']} v{data['version']}")
                print(f"  - Total Count: {data['count']}")
            except json.JSONDecodeError as e:
                print(f"\n⚠️  Could not parse JSON results: {e}")
                print(f"First 200 chars: {json_str[:200]}")

        # Statistics
        if subdomains:
            print("\n📈 Statistics:")
            print(f"  - Total subdomains: {len(subdomains)}")
            print(f"  - Unique entries: {len(set(subdomains))}")

            # Count by subdomain depth
            depths = {}
            for sub in subdomains:
                depth = sub.count('.')
                depths[depth] = depths.get(depth, 0) + 1

            print(f"  - Subdomain depths:")
            for depth in sorted(depths.keys()):
                print(f"    • Level {depth}: {depths[depth]} entries")

    except Exception as e:
        print(f"\n❌ Error during execution: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    finally:
        # Cleanup
        print("\n🧹 Cleaning up...")
        agent.cleanup()
        print("✅ Sandbox terminated")

    print("\n✨ Demo complete!")
    print(f"\nTo view full results:")
    print(f"  cat nexus-data/test-integration-team/test-integration-scan/recon/subfinder/subdomains.json")


if __name__ == "__main__":
    main()
