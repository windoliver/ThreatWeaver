#!/usr/bin/env python3
"""
HTTPx Agent Demo - End-to-End Workflow

Demonstrates the full recon workflow:
1. Subfinder discovers subdomains
2. HTTPx probes those subdomains to find live hosts
3. Displays all findings

Usage:
    python demo_httpx.py papergen.ai
"""

import os
import sys
import json
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '.'))

from src.agents.recon.subfinder_agent import SubfinderAgent
from src.agents.recon.httpx_agent import HTTPxAgent
from src.agents.backends.nexus_backend import NexusBackend
from src.config.nexus_config import get_nexus_fs


def print_banner(text):
    """Print colored banner."""
    print(f"\n{'='*80}")
    print(f"  {text}")
    print(f"{'='*80}\n")


def print_section(text):
    """Print section header."""
    print(f"\n{'-'*80}")
    print(f"  {text}")
    print(f"{'-'*80}\n")


def main():
    if len(sys.argv) < 2:
        print("Usage: python demo_httpx.py <domain>")
        print("Example: python demo_httpx.py papergen.ai")
        sys.exit(1)

    domain = sys.argv[1]
    scan_id = f"demo-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    team_id = "demo-team"

    print_banner(f"🔍 ThreatWeaver Recon Demo: {domain}")
    print(f"Scan ID: {scan_id}")
    print(f"Team ID: {team_id}")
    print(f"Target: {domain}\n")

    # Initialize Nexus backend
    print("📁 Initializing Nexus workspace...")
    nexus_fs = get_nexus_fs()
    backend = NexusBackend(scan_id, team_id, nexus_fs)
    print("✅ Nexus workspace ready\n")

    # Step 1: Subdomain Discovery with Subfinder
    print_section("STEP 1: Subdomain Discovery (Subfinder)")
    print(f"🔎 Discovering subdomains for {domain}...")
    print("⏳ This may take 1-2 minutes...\n")

    subfinder = SubfinderAgent(
        scan_id=scan_id,
        team_id=team_id,
        nexus_backend=backend
    )

    try:
        subdomains = subfinder.execute(domain, timeout=300)

        print(f"✅ Found {len(subdomains)} subdomains:\n")
        for i, subdomain in enumerate(subdomains, 1):
            print(f"  {i:3d}. {subdomain}")

        if not subdomains:
            print("⚠️  No subdomains found. Exiting.")
            subfinder.cleanup()
            return

    except Exception as e:
        print(f"❌ Subfinder failed: {e}")
        subfinder.cleanup()
        return

    # Step 2: HTTP Probing with HTTPx
    print_section("STEP 2: HTTP/HTTPS Probing (HTTPx)")
    print(f"🌐 Probing {len(subdomains)} subdomains for live HTTP/HTTPS services...")
    print("⏳ This may take 1-2 minutes...\n")

    httpx = HTTPxAgent(
        scan_id=scan_id,
        team_id=team_id,
        nexus_backend=backend
    )

    try:
        live_hosts = httpx.execute(
            targets=subdomains,
            timeout=300,
            threads=50,
            follow_redirects=True,
            tech_detect=True
        )

        print(f"✅ Found {len(live_hosts)} live hosts:\n")

        if not live_hosts:
            print("⚠️  No live hosts found.")
        else:
            # Display results in a nice table
            print(f"{'#':<4} {'URL':<40} {'Status':<8} {'Server':<20} {'Title':<30}")
            print("-" * 110)

            for i, host in enumerate(live_hosts, 1):
                url = host.get('url', '')[:40]
                status = str(host.get('status_code', 'N/A'))
                server = host.get('web_server', 'N/A')[:20]
                title = host.get('title', 'N/A')[:30]

                print(f"{i:<4} {url:<40} {status:<8} {server:<20} {title:<30}")

            # Show technology stack for hosts that have it
            print_section("Technology Stack Detected")
            for i, host in enumerate(live_hosts, 1):
                techs = host.get('technologies', [])
                if techs:
                    print(f"  {host.get('url', 'N/A')}:")
                    print(f"    Technologies: {', '.join(techs)}")

            if not any(host.get('technologies') for host in live_hosts):
                print("  No technologies detected (use -tech-detect flag for detection)")

    except Exception as e:
        print(f"❌ HTTPx failed: {e}")
    finally:
        httpx.cleanup()
        subfinder.cleanup()

    # Step 3: Show stored results
    print_section("STEP 3: Results Storage")
    print("📊 Results stored in Nexus workspace:\n")

    # Show Subfinder results path
    subfinder_path = f"/{team_id}/{scan_id}/recon/subfinder/subdomains.json"
    print(f"  Subfinder JSON: {subfinder_path}")

    # Show HTTPx results path
    httpx_path = f"/{team_id}/{scan_id}/recon/httpx/live_hosts.json"
    print(f"  HTTPx JSON:     {httpx_path}")

    # Read and display summary from stored results
    print("\n📈 Summary Statistics:")
    print(f"  Total Subdomains:  {len(subdomains)}")
    print(f"  Live Hosts:        {len(live_hosts)}")
    print(f"  Coverage:          {(len(live_hosts)/len(subdomains)*100):.1f}%" if subdomains else "  Coverage:          0.0%")

    print_banner("🎉 Scan Complete!")
    print(f"\nView full results:")
    print(f"  python view_results.py {scan_id}\n")


if __name__ == "__main__":
    # Check for E2B API key
    if not os.getenv("E2B_API_KEY"):
        print("❌ Error: E2B_API_KEY environment variable not set")
        print("Set it with: export E2B_API_KEY='your-key-here'")
        sys.exit(1)

    main()
