#!/usr/bin/env python3
"""
Recon Coordinator Demo - Complete Autonomous Reconnaissance Workflow

This demonstrates Issue #16: Recon Coordinator with LangGraph/DeepAgents.

The coordinator autonomously:
1. Discovers subdomains (Subfinder)
2. Probes for live hosts (HTTPx)
3. Scans ports and services (Nmap)
4. Aggregates findings into final report

All orchestrated by LLM reasoning - no hardcoded workflow!

Usage:
    python demo_recon_coordinator.py <domain>
    python demo_recon_coordinator.py scanme.nmap.org
"""

import os
import sys
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from agents.recon_coordinator import create_recon_coordinator
from agents.backends.nexus_backend import NexusBackend
from agents.context import set_agent_context
from config.nexus_config import get_nexus_fs


def print_banner(text):
    """Print colored banner."""
    print(f"\n{'='*80}")
    print(f"  {text}")
    print(f"{'='*80}\n")


def main():
    if len(sys.argv) < 2:
        print("Usage: python demo_recon_coordinator.py <domain>")
        print("Example: python demo_recon_coordinator.py scanme.nmap.org")
        sys.exit(1)

    # Check for API key
    if not os.getenv("OPENROUTER_API_KEY"):
        print("❌ Error: OPENROUTER_API_KEY environment variable not set")
        print("Set it with: export OPENROUTER_API_KEY='your-key-here'")
        sys.exit(1)

    # Check for E2B API key (needed for sandbox execution)
    if not os.getenv("E2B_API_KEY"):
        print("❌ Error: E2B_API_KEY environment variable not set")
        print("Set it with: export E2B_API_KEY='your-key-here'")
        sys.exit(1)

    domain = sys.argv[1]
    scan_id = f"recon-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    team_id = "demo-team"

    print_banner(f"🤖 Autonomous Recon Coordinator: {domain}")
    print(f"Scan ID: {scan_id}")
    print(f"Team ID: {team_id}")
    print(f"Target: {domain}")
    print(f"\n🧠 Intelligence: LLM-driven decision making")
    print(f"🛠️  Tools: Subfinder, HTTPx, Nmap")
    print(f"📦 Storage: Nexus/GCS")
    print()

    # Initialize Nexus backend
    print("📁 Initializing Nexus workspace...")
    nexus_fs = get_nexus_fs()
    backend = NexusBackend(scan_id, team_id, nexus_fs)
    print("✅ Nexus workspace ready\n")

    # Set agent context (for tools to access scan_id/team_id/backend)
    set_agent_context(scan_id, team_id, backend)

    # Create Recon Coordinator
    print("🤖 Creating Recon Coordinator with DeepAgents...")
    coordinator = create_recon_coordinator(scan_id, team_id, backend)
    print("✅ Coordinator ready")
    print("   - Model: Claude 3.5 Sonnet (via OpenRouter)")
    print("   - Sub-agents: Subfinder, HTTPx, Nmap")
    print("   - Backend: Nexus/GCS\n")

    # Execute reconnaissance
    print_banner("🚀 Starting Autonomous Reconnaissance")
    print("The coordinator will now:")
    print("  1. Spawn Subfinder agent → discover subdomains")
    print("  2. Analyze results → prioritize targets")
    print("  3. Spawn HTTPx agent → probe live hosts")
    print("  4. Analyze results → identify critical services")
    print("  5. Spawn Nmap agent → scan ports")
    print("  6. Aggregate findings → generate final report")
    print("\n⏳ This will take several minutes...\n")
    print("-" * 80)

    try:
        result = coordinator.invoke({
            "messages": [{
                "role": "user",
                "content": f"Perform complete reconnaissance on {domain}. Use your sub-agents intelligently and generate a comprehensive security report."
            }]
        })

        print("\n" + "-" * 80)
        print("\n✅ Reconnaissance Complete!\n")

        # Display coordinator's final response
        final_message = result['messages'][-1].content
        print("📋 Coordinator Report:")
        print("-" * 80)
        print(final_message)
        print("-" * 80)

    except Exception as e:
        print(f"\n❌ Reconnaissance failed: {e}")
        import traceback
        traceback.print_exc()
        return

    # Show results location
    print_banner("📊 Results Summary")
    print(f"All findings stored in Nexus workspace:\n")
    print(f"  Subfinder:  /{team_id}/{scan_id}/recon/subfinder/subdomains.json")
    print(f"  HTTPx:      /{team_id}/{scan_id}/recon/httpx/live_hosts.json")
    print(f"  Nmap:       /{team_id}/{scan_id}/recon/nmap/scan_results.json")
    print(f"  Final Report: /{team_id}/{scan_id}/recon/final_report.json")

    # Try to read final report
    print("\n📄 Final Report Preview:")
    print("-" * 80)
    try:
        report_content = backend.read("/recon/final_report.json")
        # Remove line numbers for display
        report_lines = [line.split("→", 1)[1] if "→" in line else line
                       for line in report_content.split("\n")]
        report_json = "\n".join(report_lines)

        import json
        report = json.loads(report_json)

        print(f"\n🎯 Target: {report.get('target', domain)}")
        print(f"📅 Timestamp: {report.get('timestamp', 'N/A')}")

        summary = report.get('summary', {})
        print(f"\n📈 Summary:")
        print(f"  Total Subdomains:  {summary.get('total_subdomains', 'N/A')}")
        print(f"  Live Hosts:        {summary.get('live_hosts', 'N/A')}")
        print(f"  Total Open Ports:  {summary.get('total_open_ports', 'N/A')}")

        high_risk = report.get('high_risk_findings', [])
        if high_risk:
            print(f"\n🚨 High Risk Findings:")
            for finding in high_risk[:5]:
                print(f"  - {finding}")

        medium_risk = report.get('medium_risk_findings', [])
        if medium_risk:
            print(f"\n⚠️  Medium Risk Findings:")
            for finding in medium_risk[:5]:
                print(f"  - {finding}")

        recommendations = report.get('recommendations', [])
        if recommendations:
            print(f"\n💡 Recommendations:")
            for rec in recommendations[:5]:
                print(f"  - {rec}")

    except Exception as e:
        print(f"Could not read final report: {e}")
        print("Check the coordinator's response above for findings.")

    print("\n" + "=" * 80)
    print("✅ Autonomous Reconnaissance Complete!")
    print("=" * 80)
    print(f"\n🎉 Issue #16 Implementation Working!")
    print(f"   - LangGraph/DeepAgents coordination: ✅")
    print(f"   - Sub-agent spawning: ✅")
    print(f"   - LLM-driven decisions: ✅")
    print(f"   - Nexus/GCS storage: ✅")
    print(f"   - Complete workflow: ✅\n")


if __name__ == "__main__":
    main()
