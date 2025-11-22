#!/usr/bin/env python3
"""
View stored Subfinder results from Nexus workspace.

Usage:
    python view_results.py
    python view_results.py --scan-id my-scan --team-id my-team
    python view_results.py --json  # Show full JSON
"""

import argparse
import json
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.config import get_nexus_fs
from src.agents.backends.nexus_backend import NexusBackend


def strip_line_numbers(content: str) -> str:
    """Remove line numbers from Nexus read output."""
    lines = []
    for line in content.split("\n"):
        if "→" in line:
            _, text = line.split("→", 1)
            lines.append(text)
        else:
            lines.append(line)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="View Subfinder results from Nexus")
    parser.add_argument("--scan-id", default="demo-scan", help="Scan ID")
    parser.add_argument("--team-id", default="demo-team", help="Team ID")
    parser.add_argument("--json", action="store_true", help="Show full JSON")
    parser.add_argument("--raw", action="store_true", help="Show raw output")

    args = parser.parse_args()

    print(f"🔍 Reading results for {args.team_id}/{args.scan_id}")
    print("=" * 60)

    # Initialize Nexus
    nx = get_nexus_fs()
    backend = NexusBackend(args.scan_id, args.team_id, nx)

    # List all files in workspace
    print("\n📁 Files in workspace:")
    try:
        files = backend.get_all_files()
        for path in sorted(files.keys()):
            size = len(files[path])
            print(f"  - {path} ({size:,} bytes)")
    except Exception as e:
        print(f"  Error: {e}")
        sys.exit(1)

    # Read JSON results (read all lines, not just first 2000)
    print("\n📊 Scan Results:")
    json_content = backend.read("/recon/subfinder/subdomains.json", limit=999999)

    if json_content.startswith("Error:"):
        print(f"  ❌ {json_content}")
        sys.exit(1)

    # Parse JSON
    json_str = strip_line_numbers(json_content)

    try:
        data = json.loads(json_str)

        print(f"\n  Domain: {data['domain']}")
        print(f"  Scan ID: {data['scan_id']}")
        print(f"  Team ID: {data['team_id']}")
        print(f"  Timestamp: {data['timestamp']}")
        print(f"  Tool: {data['tool']} v{data['version']}")
        print(f"  Total Subdomains: {data['count']:,}")

        print(f"\n📋 Subdomains (first 20):")
        for i, subdomain in enumerate(data['subdomains'][:20], 1):
            print(f"  {i:3d}. {subdomain}")

        if len(data['subdomains']) > 20:
            print(f"\n  ... and {len(data['subdomains']) - 20:,} more")

        # Full JSON output
        if args.json:
            print("\n📄 Full JSON:")
            print(json.dumps(data, indent=2))

        # Statistics
        print(f"\n📈 Statistics:")
        print(f"  - Total: {len(data['subdomains']):,}")
        print(f"  - Unique: {len(set(data['subdomains'])):,}")

        # Subdomain depth analysis
        depths = {}
        for sub in data['subdomains']:
            depth = sub.count('.')
            depths[depth] = depths.get(depth, 0) + 1

        print(f"  - Depth distribution:")
        for depth in sorted(depths.keys()):
            print(f"    • Level {depth}: {depths[depth]:,} entries")

    except json.JSONDecodeError as e:
        print(f"  ❌ Could not parse JSON: {e}")
        print(f"\nFirst 500 chars of content:")
        print(json_str[:500])
        sys.exit(1)

    # Raw output
    if args.raw:
        print("\n📄 Raw Subfinder Output:")
        print("=" * 60)
        raw_content = backend.read("/recon/subfinder/raw_output.txt", limit=999999)
        if not raw_content.startswith("Error:"):
            raw_text = strip_line_numbers(raw_content)
            # Show first 50 lines
            lines = raw_text.split("\n")
            for line in lines[:50]:
                print(line)
            if len(lines) > 50:
                print(f"\n... and {len(lines) - 50} more lines")
        else:
            print(f"  ❌ {raw_content}")

    print("\n✨ Done!")


if __name__ == "__main__":
    main()
