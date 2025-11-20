"""
Diff detection for cross-scan comparisons.

This module provides utilities to detect changes between current and previous scans.
It powers adaptive workflows by identifying new/removed/fixed items.

Use Cases:
- "50 new subdomains since last scan" → run deep OSINT with Amass
- "2 vulnerabilities fixed" → report to user
- "Attack surface grew 30%" → alert security team
"""

from typing import List, TypedDict

from src.agents.handoffs.schemas import AssessmentHandoff, ReconHandoff


class HandoffDiff(TypedDict, total=False):
    """
    Diff results between current and previous handoffs.

    Fields:
        new_items: Items added since previous scan
        removed_items: Items removed since previous scan
        unchanged_items: Items present in both scans
        growth_percentage: Percentage growth (can be negative)
        recommendation: LLM recommendation based on diff
    """

    new_items: List[str]
    removed_items: List[str]
    unchanged_items: List[str]
    growth_percentage: float
    recommendation: str


class DiffDetector:
    """
    Detect changes between current and previous handoffs.

    This class provides static methods to compute diffs for various handoff fields.
    It's used by handoff analysis nodes to make adaptive workflow decisions.

    Example:
        >>> current_recon = {"subdomains": ["api.target.com", "admin.target.com", "new.target.com"]}
        >>> previous_recon = {"subdomains": ["api.target.com", "admin.target.com"]}
        >>> diff = DiffDetector.diff_subdomains(current_recon, previous_recon)
        >>> print(diff["new_items"])
        ["new.target.com"]
    """

    @staticmethod
    def diff_subdomains(
        current: ReconHandoff,
        previous: ReconHandoff,
    ) -> HandoffDiff:
        """
        Compute diff for subdomains.

        Args:
            current: Current scan's recon handoff
            previous: Previous scan's recon handoff

        Returns:
            HandoffDiff with new/removed/unchanged subdomains

        Example:
            >>> diff = DiffDetector.diff_subdomains(current_recon, previous_recon)
            >>> if len(diff["new_items"]) > 20:
            ...     # Run deep OSINT with Amass
            ...     workflow.next_step = "deep_osint"
        """
        current_subdomains = set(current.get("subdomains", []))
        previous_subdomains = set(previous.get("subdomains", []))

        new = list(current_subdomains - previous_subdomains)
        removed = list(previous_subdomains - current_subdomains)
        unchanged = list(current_subdomains & previous_subdomains)

        # Calculate growth percentage
        if len(previous_subdomains) > 0:
            growth = ((len(current_subdomains) - len(previous_subdomains)) / len(previous_subdomains)) * 100
        else:
            growth = 100.0 if len(current_subdomains) > 0 else 0.0

        # Generate recommendation
        recommendation = ""
        if len(new) > 20:
            recommendation = "RECOMMEND_DEEP_OSINT"  # Run Amass for comprehensive enumeration
        elif len(new) > 5:
            recommendation = "MODERATE_GROWTH"  # Normal scan progression
        elif len(new) == 0:
            recommendation = "NO_CHANGES"  # Skip redundant scans
        else:
            recommendation = "MINIMAL_GROWTH"

        return HandoffDiff(
            new_items=sorted(new),
            removed_items=sorted(removed),
            unchanged_items=sorted(unchanged),
            growth_percentage=round(growth, 2),
            recommendation=recommendation,
        )

    @staticmethod
    def diff_vulnerabilities(
        current: AssessmentHandoff,
        previous: AssessmentHandoff,
    ) -> HandoffDiff:
        """
        Compute diff for vulnerabilities.

        Args:
            current: Current scan's assessment handoff
            previous: Previous scan's assessment handoff

        Returns:
            HandoffDiff with new/fixed vulnerabilities

        Example:
            >>> diff = DiffDetector.diff_vulnerabilities(current_assessment, previous_assessment)
            >>> if len(diff["removed_items"]) > 0:
            ...     print(f"Fixed: {diff['removed_items']}")
        """
        # Extract vulnerability IDs/templates for comparison
        current_vulns = set(
            vuln.get("template") or vuln.get("id") or str(vuln)
            for vuln in current.get("vulnerabilities", [])
        )
        previous_vulns = set(
            vuln.get("template") or vuln.get("id") or str(vuln)
            for vuln in previous.get("vulnerabilities", [])
        )

        new = list(current_vulns - previous_vulns)
        fixed = list(previous_vulns - current_vulns)  # "removed" means fixed!
        unchanged = list(current_vulns & previous_vulns)

        # Calculate growth percentage (negative = improvement!)
        if len(previous_vulns) > 0:
            growth = ((len(current_vulns) - len(previous_vulns)) / len(previous_vulns)) * 100
        else:
            growth = 100.0 if len(current_vulns) > 0 else 0.0

        # Generate recommendation
        recommendation = ""
        if len(new) > 0 and len(fixed) == 0:
            recommendation = "SECURITY_DEGRADED"  # New vulns, nothing fixed
        elif len(new) == 0 and len(fixed) > 0:
            recommendation = "SECURITY_IMPROVED"  # No new vulns, some fixed
        elif len(new) > 0 and len(fixed) > 0:
            recommendation = "MIXED_CHANGES"  # Both new and fixed
        else:
            recommendation = "NO_CHANGES"

        return HandoffDiff(
            new_items=sorted(new),
            removed_items=sorted(fixed),  # "removed" = fixed vulnerabilities
            unchanged_items=sorted(unchanged),
            growth_percentage=round(growth, 2),
            recommendation=recommendation,
        )

    @staticmethod
    def diff_technologies(
        current: ReconHandoff,
        previous: ReconHandoff,
    ) -> HandoffDiff:
        """
        Compute diff for detected technologies.

        Args:
            current: Current scan's recon handoff
            previous: Previous scan's recon handoff

        Returns:
            HandoffDiff with new/removed technologies

        Example:
            >>> diff = DiffDetector.diff_technologies(current_recon, previous_recon)
            >>> if "wordpress" in diff["new_items"]:
            ...     # Run WordPress-specific scanners
            ...     workflow.add_task("wpscan")
        """
        current_tech = set(current.get("technologies", []))
        previous_tech = set(previous.get("technologies", []))

        new = list(current_tech - previous_tech)
        removed = list(previous_tech - current_tech)
        unchanged = list(current_tech & previous_tech)

        # Calculate growth percentage
        if len(previous_tech) > 0:
            growth = ((len(current_tech) - len(previous_tech)) / len(previous_tech)) * 100
        else:
            growth = 100.0 if len(current_tech) > 0 else 0.0

        # Generate recommendation
        recommendation = ""
        if any(tech in new for tech in ["wordpress", "joomla", "drupal"]):
            recommendation = "RUN_CMS_SCANNERS"
        elif any(tech in new for tech in ["nginx", "apache", "iis"]):
            recommendation = "RUN_WEB_SCANNERS"
        else:
            recommendation = "NO_SPECIAL_ACTION"

        return HandoffDiff(
            new_items=sorted(new),
            removed_items=sorted(removed),
            unchanged_items=sorted(unchanged),
            growth_percentage=round(growth, 2),
            recommendation=recommendation,
        )

    @staticmethod
    def summarize_diff(diff: HandoffDiff, field_name: str) -> str:
        """
        Generate human-readable diff summary.

        Args:
            diff: HandoffDiff result
            field_name: Name of field being diffed (e.g., "subdomains")

        Returns:
            Human-readable summary string

        Example:
            >>> diff = DiffDetector.diff_subdomains(current, previous)
            >>> summary = DiffDetector.summarize_diff(diff, "subdomains")
            >>> print(summary)
            "Found 15 new subdomains (+30.0% growth). Recommendation: RECOMMEND_DEEP_OSINT"
        """
        new_count = len(diff["new_items"])
        removed_count = len(diff["removed_items"])
        growth = diff["growth_percentage"]
        recommendation = diff["recommendation"]

        parts = []

        if new_count > 0:
            parts.append(f"Found {new_count} new {field_name}")

        if removed_count > 0:
            parts.append(f"{removed_count} {field_name} removed")

        if growth != 0:
            sign = "+" if growth > 0 else ""
            parts.append(f"({sign}{growth}% growth)")

        if recommendation:
            parts.append(f"Recommendation: {recommendation}")

        return ". ".join(parts) if parts else f"No changes in {field_name}"
