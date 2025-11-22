#!/usr/bin/env python3
"""
Nmap Agent Demo - Complete Recon Workflow

Demonstrates the full three-stage recon workflow:
1. Subfinder discovers subdomains
2. HTTPx probes subdomains to find live hosts
3. Nmap scans live hosts for open ports and services

Usage:
    python demo_nmap.py scanme.nmap.org
    python demo_nmap.py scanme.nmap.org --profile aggressive
    python demo_nmap.py scanme.nmap.org --ports 22,80,443,8080
"""

import os
import sys
import argparse
import json
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '.'))

from src.agents.recon.subfinder_agent import SubfinderAgent
from src.agents.recon.httpx_agent import HTTPxAgent
from src.agents.recon.nmap_agent import NmapAgent, ScanProfile
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


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Complete recon workflow: Subfinder → HTTPx → Nmap")
    parser.add_argument("domain", help="Target domain to scan")
    parser.add_argument(
        "--profile",
        choices=["stealth", "default", "aggressive"],
        default="default",
        help="Nmap scan profile (default: default)"
    )
    parser.add_argument(
        "--ports",
        help="Port specification (e.g., '22,80,443' or '1-1000'). Default: top 1000 ports"
    )
    parser.add_argument(
        "--skip-subfinder",
        action="store_true",
        help="Skip subdomain discovery (scan domain only)"
    )
    parser.add_argument(
        "--skip-httpx",
        action="store_true",
        help="Skip HTTP probing (scan all subdomains)"
    )

    return parser.parse_args()


def main():
    args = parse_args()

    domain = args.domain
    scan_id = f"demo-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    team_id = "demo-team"

    print_banner(f"🔍 ThreatWeaver Complete Recon: {domain}")
    print(f"Scan ID: {scan_id}")
    print(f"Team ID: {team_id}")
    print(f"Target: {domain}")
    print(f"Nmap Profile: {args.profile}")
    if args.ports:
        print(f"Ports: {args.ports}")
    print()

    # Initialize Nexus backend
    print("📁 Initializing Nexus workspace...")
    nexus_fs = get_nexus_fs()
    backend = NexusBackend(scan_id, team_id, nexus_fs)
    print("✅ Nexus workspace ready\n")

    targets_for_nmap = [domain]  # Default: scan the domain itself

    # Stage 1: Subfinder (optional)
    if not args.skip_subfinder:
        print_section("STAGE 1: Subdomain Discovery (Subfinder)")
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
            for i, subdomain in enumerate(subdomains[:10], 1):
                print(f"  {i:3d}. {subdomain}")

            if len(subdomains) > 10:
                print(f"  ... and {len(subdomains) - 10} more")

            if subdomains:
                targets_for_nmap = subdomains
            else:
                print(f"⚠️  No subdomains found, will scan {domain} only")

        except Exception as e:
            print(f"❌ Subfinder failed: {e}")
            subfinder.cleanup()
            return
        finally:
            subfinder.cleanup()

    # Stage 2: HTTPx (optional)
    live_hosts = []
    if not args.skip_httpx and targets_for_nmap:
        print_section("STAGE 2: HTTP/HTTPS Probing (HTTPx)")
        print(f"🌐 Probing {len(targets_for_nmap)} targets for live HTTP/HTTPS services...")
        print("⏳ This may take 1-2 minutes...\n")

        httpx = HTTPxAgent(
            scan_id=scan_id,
            team_id=team_id,
            nexus_backend=backend
        )

        try:
            live_hosts = httpx.execute(
                targets=targets_for_nmap,
                timeout=300,
                threads=50,
                follow_redirects=True,
                tech_detect=True
            )

            print(f"✅ Found {len(live_hosts)} live hosts:\n")

            if live_hosts:
                # Extract hostnames for Nmap scanning
                targets_for_nmap = [h.get('host', h.get('url', '')) for h in live_hosts]
                # Clean URLs to just hostnames
                targets_for_nmap = [t.replace('https://', '').replace('http://', '').split('/')[0]
                                   for t in targets_for_nmap]

                # Display summary
                print(f"{'#':<4} {'Host':<40} {'Status':<8} {'Title':<30}")
                print("-" * 90)
                for i, host in enumerate(live_hosts[:10], 1):
                    hostname = host.get('host', 'N/A')[:40]
                    status = str(host.get('status_code', 'N/A'))
                    title = host.get('title', 'N/A')[:30]
                    print(f"{i:<4} {hostname:<40} {status:<8} {title:<30}")

                if len(live_hosts) > 10:
                    print(f"  ... and {len(live_hosts) - 10} more")
            else:
                print("⚠️  No live hosts found, will scan original targets")
                # Fall back to original targets

        except Exception as e:
            print(f"❌ HTTPx failed: {e}")
            print("Continuing with original targets...")
        finally:
            httpx.cleanup()

    # Stage 3: Nmap
    print_section("STAGE 3: Port Scanning (Nmap)")
    print(f"🔍 Scanning {len(targets_for_nmap)} targets for open ports...")
    print(f"Profile: {args.profile}")
    if args.ports:
        print(f"Ports: {args.ports}")
    print("⏳ This may take several minutes...\n")

    nmap = NmapAgent(
        scan_id=scan_id,
        team_id=team_id,
        nexus_backend=backend
    )

    results = {"hosts": [], "scan_stats": {}}  # Initialize results
    try:
        # Map profile string to enum
        profile_map = {
            "stealth": ScanProfile.STEALTH,
            "default": ScanProfile.DEFAULT,
            "aggressive": ScanProfile.AGGRESSIVE
        }
        profile = profile_map[args.profile]

        results = nmap.execute(
            targets=targets_for_nmap,
            profile=profile,
            ports=args.ports,
            timeout=3600  # 1 hour max
        )

        print(f"✅ Scan complete!\n")

        # Display results
        if not results['hosts']:
            print("⚠️  No live hosts detected by Nmap")
        else:
            print(f"Found {len(results['hosts'])} hosts with {results.get('total_open_ports', 0)} total open ports:\n")

            for i, host in enumerate(results['hosts'], 1):
                ip = host.get('ip', 'N/A')
                hostnames = host.get('hostnames', [])
                ports = host.get('ports', [])
                os_matches = host.get('os_matches', [])

                print(f"[{i}] {ip}")
                if hostnames:
                    print(f"    Hostnames: {', '.join(hostnames)}")

                if ports:
                    print(f"    Open Ports ({len(ports)}):")
                    for port in ports[:10]:  # Show first 10 ports
                        service = port.get('service', 'unknown')
                        product = port.get('product', '')
                        version = port.get('version', '')
                        port_num = port.get('port', 0)

                        service_info = f"{service}"
                        if product:
                            service_info += f" ({product}"
                            if version:
                                service_info += f" {version}"
                            service_info += ")"

                        print(f"      - {port_num}/{port.get('protocol', 'tcp')}: {service_info}")

                    if len(ports) > 10:
                        print(f"      ... and {len(ports) - 10} more ports")

                if os_matches:
                    top_os = os_matches[0]
                    print(f"    OS: {top_os.get('name', 'Unknown')} ({top_os.get('accuracy', 0)}% accuracy)")

                print()

    except Exception as e:
        print(f"❌ Nmap failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        nmap.cleanup()

    # Summary
    print_section("SCAN SUMMARY")
    print(f"📊 Results stored in Nexus workspace:\n")

    if not args.skip_subfinder:
        print(f"  Subfinder: /{team_id}/{scan_id}/recon/subfinder/subdomains.json")
    if not args.skip_httpx:
        print(f"  HTTPx:     /{team_id}/{scan_id}/recon/httpx/live_hosts.json")
    print(f"  Nmap:      /{team_id}/{scan_id}/recon/nmap/scan_results.json")

    print("\n📈 Summary Statistics:")
    if not args.skip_subfinder:
        print(f"  Subdomains Discovered: {len(targets_for_nmap) if targets_for_nmap else 0}")
    if live_hosts:
        print(f"  Live Hosts Found:      {len(live_hosts)}")
    print(f"  Hosts Scanned:         {len(results.get('hosts', []))}")
    print(f"  Total Open Ports:      {sum(len(h.get('ports', [])) for h in results.get('hosts', []))}")

    print_banner("🎉 Complete Recon Scan Finished!")
    print(f"\nView full results:")
    print(f"  python view_results.py {scan_id}\n")


if __name__ == "__main__":
    # Check for E2B API key
    if not os.getenv("E2B_API_KEY"):
        print("❌ Error: E2B_API_KEY environment variable not set")
        print("Set it with: export E2B_API_KEY='your-key-here'")
        sys.exit(1)

    main()
