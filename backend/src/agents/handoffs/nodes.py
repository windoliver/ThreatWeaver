"""
Handoff analysis nodes for LangGraph workflows.

These nodes implement Layer 1 (in-memory handoffs) of the hybrid architecture.
They analyze current scan results, compare with historical data, and make
adaptive workflow decisions.

Use Cases:
- recon_to_assessment_handoff: Prioritize targets based on diff
- assessment_to_exploit_handoff: Suggest exploits for new vulnerabilities
- finalize_scan: Persist ephemeral handoffs to Nexus

Reference:
- architecture.md Section 4 (Layer 1: In-Memory Handoffs)
"""

from typing import Any, Dict

from nexus.core.nexus_fs import NexusFS

from src.agents.handoffs.diff import DiffDetector
from src.agents.handoffs.persistence import HandoffPersistence
from src.agents.handoffs.schemas import ScanState


def recon_to_assessment_handoff(
    state: ScanState,
    nexus_fs: NexusFS,
) -> ScanState:
    """
    Handoff: ReconEngine → AssessmentEngine.

    This node is called after recon completes. It:
    1. Loads previous recon handoff from Nexus
    2. Computes diff (new/removed subdomains, tech stack changes)
    3. Updates state with diff analysis
    4. Makes adaptive workflow decision (deep OSINT, vuln scan, etc.)

    Args:
        state: Current LangGraph state (with recon_handoff populated)
        nexus_fs: NexusFS instance for loading historical data

    Returns:
        Updated state with diff analysis and next_step decision

    Performance:
    - In-memory operation (no disk I/O except loading previous handoff)
    - 3% faster than writing to S3 during active scan

    Example:
        >>> # In LangGraph workflow
        >>> graph.add_node("recon_to_assessment", recon_to_assessment_handoff)
        >>> graph.add_edge("recon_complete", "recon_to_assessment")
    """
    persistence = HandoffPersistence(nexus_fs)

    # Load historical context from Nexus
    state["previous_recon"] = persistence.load_previous_recon(
        team_id=state["team_id"],
        target=state["target"],
    )

    # If this is first scan, proceed to vuln scan
    if not state.get("previous_recon"):
        state["next_step"] = "vuln_scan"
        state["new_subdomains"] = state.get("recon_handoff", {}).get("subdomains", [])
        state["removed_subdomains"] = []
        return state

    # Compute diff for subdomains
    subdomain_diff = DiffDetector.diff_subdomains(
        current=state.get("recon_handoff", {}),
        previous=state["previous_recon"],
    )

    # Update state with diff results
    state["new_subdomains"] = subdomain_diff["new_items"]
    state["removed_subdomains"] = subdomain_diff["removed_items"]

    # Make adaptive workflow decision based on diff
    recommendation = subdomain_diff["recommendation"]

    if recommendation == "RECOMMEND_DEEP_OSINT":
        # Significant growth (>20 new subdomains) → run deep OSINT with Amass
        state["next_step"] = "deep_osint"
        state["metadata"] = state.get("metadata", {})
        state["metadata"]["reason"] = (
            f"Found {len(subdomain_diff['new_items'])} new subdomains "
            f"({subdomain_diff['growth_percentage']}% growth). Running Amass for comprehensive enumeration."
        )

    elif recommendation == "NO_CHANGES":
        # No new subdomains → skip redundant scans, go straight to report
        state["next_step"] = "report"
        state["metadata"] = state.get("metadata", {})
        state["metadata"]["reason"] = "No new subdomains detected. Skipping redundant scans."

    else:
        # Normal progression → vuln scan
        state["next_step"] = "vuln_scan"
        state["metadata"] = state.get("metadata", {})
        state["metadata"]["reason"] = (
            f"Found {len(subdomain_diff['new_items'])} new subdomains. Proceeding to vulnerability scan."
        )

    # Also compute tech stack diff for targeting
    if state.get("previous_recon", {}).get("technologies"):
        tech_diff = DiffDetector.diff_technologies(
            current=state.get("recon_handoff", {}),
            previous=state["previous_recon"],
        )

        # Store tech diff for assessment phase
        state["metadata"]["tech_diff"] = {
            "new_technologies": tech_diff["new_items"],
            "recommendation": tech_diff["recommendation"],
        }

    return state


def assessment_to_exploit_handoff(
    state: ScanState,
    nexus_fs: NexusFS,
) -> ScanState:
    """
    Handoff: AssessmentEngine → ExploitEngine.

    This node is called after vulnerability assessment completes. It:
    1. Loads previous assessment handoff from Nexus
    2. Computes diff (new/fixed vulnerabilities)
    3. Prioritizes new critical findings
    4. Suggests exploitation strategies

    Args:
        state: Current LangGraph state (with assessment_handoff populated)
        nexus_fs: NexusFS instance for loading historical data

    Returns:
        Updated state with vuln diff and exploit suggestions

    Example:
        >>> # In LangGraph workflow
        >>> graph.add_node("assessment_to_exploit", assessment_to_exploit_handoff)
        >>> graph.add_edge("assessment_complete", "assessment_to_exploit")
    """
    persistence = HandoffPersistence(nexus_fs)

    # Load historical context from Nexus
    state["previous_assessment"] = persistence.load_previous_assessment(
        team_id=state["team_id"],
        target=state["target"],
    )

    # If this is first scan, proceed to exploit (if critical findings exist)
    if not state.get("previous_assessment"):
        critical_findings = state.get("assessment_handoff", {}).get("critical_findings", [])

        if len(critical_findings) > 0:
            state["next_step"] = "exploit"
        else:
            state["next_step"] = "report"

        state["new_vulnerabilities"] = state.get("assessment_handoff", {}).get("vulnerabilities", [])
        state["fixed_vulnerabilities"] = []
        return state

    # Compute diff for vulnerabilities
    vuln_diff = DiffDetector.diff_vulnerabilities(
        current=state.get("assessment_handoff", {}),
        previous=state["previous_assessment"],
    )

    # Update state with diff results
    # Convert vuln IDs back to full vulnerability dicts for new vulns
    current_vulns = state.get("assessment_handoff", {}).get("vulnerabilities", [])
    new_vuln_ids = set(vuln_diff["new_items"])

    state["new_vulnerabilities"] = [
        vuln
        for vuln in current_vulns
        if (vuln.get("template") or vuln.get("id") or str(vuln)) in new_vuln_ids
    ]

    # Fixed vulnerabilities (use previous scan's data)
    previous_vulns = state["previous_assessment"].get("vulnerabilities", [])
    fixed_vuln_ids = set(vuln_diff["removed_items"])

    state["fixed_vulnerabilities"] = [
        vuln
        for vuln in previous_vulns
        if (vuln.get("template") or vuln.get("id") or str(vuln)) in fixed_vuln_ids
    ]

    # Make workflow decision based on diff
    recommendation = vuln_diff["recommendation"]

    if recommendation == "SECURITY_DEGRADED":
        # New vulnerabilities found → run exploitation
        state["next_step"] = "exploit"
        state["metadata"] = state.get("metadata", {})
        state["metadata"]["reason"] = (
            f"Found {len(state['new_vulnerabilities'])} new vulnerabilities. "
            f"Attempting automated exploitation."
        )

    elif recommendation == "SECURITY_IMPROVED":
        # No new vulnerabilities, some fixed → report good news
        state["next_step"] = "report"
        state["metadata"] = state.get("metadata", {})
        state["metadata"]["reason"] = (
            f"Security improved: {len(state['fixed_vulnerabilities'])} vulnerabilities fixed. "
            f"No new vulnerabilities detected."
        )

    elif recommendation == "MIXED_CHANGES":
        # Both new and fixed → run exploitation for new ones
        state["next_step"] = "exploit"
        state["metadata"] = state.get("metadata", {})
        state["metadata"]["reason"] = (
            f"Mixed changes: {len(state['new_vulnerabilities'])} new, "
            f"{len(state['fixed_vulnerabilities'])} fixed. Focusing on new vulnerabilities."
        )

    else:
        # No changes → report
        state["next_step"] = "report"
        state["metadata"] = state.get("metadata", {})
        state["metadata"]["reason"] = "No changes in vulnerability status."

    return state


def finalize_scan(
    state: ScanState,
    nexus_fs: NexusFS,
) -> ScanState:
    """
    Persist ephemeral handoffs to Nexus at scan end.

    This node is called at the end of a scan workflow. It saves the
    ephemeral in-memory handoffs to Nexus for use in future scans.

    Args:
        state: Final LangGraph state (with all handoffs populated)
        nexus_fs: NexusFS instance for persisting data

    Returns:
        Updated state (unchanged, but handoffs are persisted)

    Storage:
        /{team_id}/{scan_id}/handoffs/recon_handoff.json
        /{team_id}/{scan_id}/handoffs/assessment_handoff.json

    Example:
        >>> # In LangGraph workflow
        >>> graph.add_node("finalize_scan", finalize_scan)
        >>> graph.add_edge("report_complete", "finalize_scan")
    """
    persistence = HandoffPersistence(nexus_fs)

    # Save recon handoff if present
    if state.get("recon_handoff"):
        persistence.save_recon_handoff(
            scan_id=state["scan_id"],
            team_id=state["team_id"],
            handoff=state["recon_handoff"],
        )

    # Save assessment handoff if present
    if state.get("assessment_handoff"):
        persistence.save_assessment_handoff(
            scan_id=state["scan_id"],
            team_id=state["team_id"],
            handoff=state["assessment_handoff"],
        )

    # Update metadata to indicate persistence
    state["metadata"] = state.get("metadata", {})
    state["metadata"]["handoffs_persisted"] = True
    state["metadata"]["handoff_location"] = f"/{state['team_id']}/{state['scan_id']}/handoffs/"

    return state
