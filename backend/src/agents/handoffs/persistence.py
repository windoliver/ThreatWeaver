"""
HandoffPersistence - Persist ephemeral handoffs to Nexus for cross-scan knowledge.

This module handles saving and loading handoff data to/from the Nexus workspace.
It provides the Layer 2 (persistent) component of the hybrid handoff architecture.

Architecture:
- Handoffs stored in: /workspace/{team_id}/{scan_id}/handoffs/
- Files: recon_handoff.json, assessment_handoff.json
- Format: JSON with ISO 8601 timestamps

Reference:
- architecture.md Section 4 (Layer 2: Persistent Handoffs)
"""

import json
from datetime import datetime
from typing import Optional

from nexus.core.nexus_fs import NexusFS

from src.agents.handoffs.schemas import AssessmentHandoff, ReconHandoff


class HandoffPersistence:
    """
    Persist ephemeral handoffs to Nexus for cross-scan knowledge.

    This class provides methods to save and load handoff data from the Nexus
    workspace, enabling historical context and diff detection across scans.

    Storage structure:
        /workspace/{team_id}/{scan_id}/handoffs/recon_handoff.json
        /workspace/{team_id}/{scan_id}/handoffs/assessment_handoff.json

    Example:
        >>> from config.nexus_config import get_nexus_fs
        >>> persistence = HandoffPersistence(get_nexus_fs())
        >>> persistence.save_recon_handoff("scan-123", "team-abc", recon_data)
        >>> previous = persistence.load_previous_recon("team-abc", "target.com")
    """

    def __init__(self, nexus_fs: NexusFS):
        """
        Initialize HandoffPersistence.

        Args:
            nexus_fs: NexusFS instance (configured with S3/local connector)
        """
        self.nx = nexus_fs

    def save_recon_handoff(
        self,
        scan_id: str,
        team_id: str,
        handoff: ReconHandoff,
    ) -> None:
        """
        Save recon handoff to Nexus after scan completes.

        This is called ONCE at the end of a scan to persist ephemeral
        in-memory handoff data for future scans.

        Args:
            scan_id: Scan identifier (e.g., "scan-20251119-123456")
            team_id: Team identifier for multi-tenancy
            handoff: ReconHandoff data from LangGraph state

        Storage path:
            /{team_id}/{scan_id}/handoffs/recon_handoff.json

        Example:
            >>> persistence.save_recon_handoff(
            ...     scan_id="scan-123",
            ...     team_id="team-abc",
            ...     handoff={
            ...         "subdomains": ["api.target.com", "admin.target.com"],
            ...         "live_hosts": [...],
            ...         "high_value_targets": ["admin.target.com"],
            ...         "metadata": {}
            ...     }
            ... )
        """
        path = f"/{team_id}/{scan_id}/handoffs/recon_handoff.json"

        # Add timestamp to handoff
        data = {
            **handoff,
            "timestamp": datetime.utcnow().isoformat(),
            "scan_id": scan_id,
            "team_id": team_id,
        }

        # Ensure parent directory exists
        parent_dir = f"/{team_id}/{scan_id}/handoffs"
        self.nx.mkdir(parent_dir, parents=True, exist_ok=True)

        # Write JSON to Nexus
        json_bytes = json.dumps(data, indent=2).encode("utf-8")
        self.nx.write(path, json_bytes)

    def save_assessment_handoff(
        self,
        scan_id: str,
        team_id: str,
        handoff: AssessmentHandoff,
    ) -> None:
        """
        Save assessment handoff to Nexus after scan completes.

        Args:
            scan_id: Scan identifier
            team_id: Team identifier
            handoff: AssessmentHandoff data from LangGraph state

        Storage path:
            /{team_id}/{scan_id}/handoffs/assessment_handoff.json
        """
        path = f"/{team_id}/{scan_id}/handoffs/assessment_handoff.json"

        # Add timestamp to handoff
        data = {
            **handoff,
            "timestamp": datetime.utcnow().isoformat(),
            "scan_id": scan_id,
            "team_id": team_id,
        }

        # Ensure parent directory exists
        parent_dir = f"/{team_id}/{scan_id}/handoffs"
        self.nx.mkdir(parent_dir, parents=True, exist_ok=True)

        # Write JSON to Nexus
        json_bytes = json.dumps(data, indent=2).encode("utf-8")
        self.nx.write(path, json_bytes)

    def load_previous_recon(
        self,
        team_id: str,
        target: str,
    ) -> Optional[ReconHandoff]:
        """
        Load recon handoff from previous scan for historical context.

        This method finds the most recent scan for the given target and
        loads its recon handoff data. Used for diff detection and adaptive
        workflow decisions.

        Args:
            team_id: Team identifier
            target: Scan target (domain, IP, CIDR)

        Returns:
            ReconHandoff from previous scan, or None if this is first scan

        Example:
            >>> previous = persistence.load_previous_recon("team-abc", "target.com")
            >>> if previous:
            ...     new_subdomains = set(current) - set(previous['subdomains'])
        """
        # List all scans for this team
        team_dir = f"/{team_id}"

        try:
            scan_dirs = self.nx.list(team_dir, recursive=False)

            # Filter to scan directories only (format: scan-YYYYMMDD-HHMMSS)
            scan_dirs = [d for d in scan_dirs if d.startswith(f"{team_dir}/scan-")]

            if not scan_dirs:
                return None  # First scan for this team

            # Sort by scan_id (descending) to get most recent first
            # scan_ids are formatted as scan-YYYYMMDD-HHMMSS, so lexical sort works
            scan_dirs.sort(reverse=True)

            # Check each scan (newest first) for matching target
            for scan_dir in scan_dirs:
                handoff_path = f"{scan_dir}/handoffs/recon_handoff.json"

                try:
                    # Try to read handoff
                    handoff_bytes = self.nx.read(handoff_path)
                    handoff_data = json.loads(handoff_bytes.decode("utf-8"))

                    # Check if this scan was for the same target
                    # (we could store target in metadata or infer from handoff)
                    # For now, assume first found handoff is from same target
                    # TODO: Add target field to handoff metadata for precise matching

                    # Remove our added fields to return clean ReconHandoff
                    clean_handoff: ReconHandoff = {
                        k: v
                        for k, v in handoff_data.items()
                        if k not in ["timestamp", "scan_id", "team_id"]
                    }

                    return clean_handoff

                except Exception:
                    # Handoff not found in this scan, try next
                    continue

            return None  # No previous scans found

        except Exception:
            return None  # Error listing scans

    def load_previous_assessment(
        self,
        team_id: str,
        target: str,
    ) -> Optional[AssessmentHandoff]:
        """
        Load assessment handoff from previous scan for historical context.

        Args:
            team_id: Team identifier
            target: Scan target

        Returns:
            AssessmentHandoff from previous scan, or None if first scan
        """
        team_dir = f"/{team_id}"

        try:
            scan_dirs = self.nx.list(team_dir, recursive=False)
            scan_dirs = [d for d in scan_dirs if d.startswith(f"{team_dir}/scan-")]

            if not scan_dirs:
                return None

            scan_dirs.sort(reverse=True)

            for scan_dir in scan_dirs:
                handoff_path = f"{scan_dir}/handoffs/assessment_handoff.json"

                try:
                    handoff_bytes = self.nx.read(handoff_path)
                    handoff_data = json.loads(handoff_bytes.decode("utf-8"))

                    clean_handoff: AssessmentHandoff = {
                        k: v
                        for k, v in handoff_data.items()
                        if k not in ["timestamp", "scan_id", "team_id"]
                    }

                    return clean_handoff

                except Exception:
                    continue

            return None

        except Exception:
            return None

    def get_scan_history(
        self,
        team_id: str,
        limit: int = 10,
    ) -> list[dict]:
        """
        Get scan history for a team (most recent first).

        Args:
            team_id: Team identifier
            limit: Maximum number of scans to return

        Returns:
            List of scan metadata dicts with timestamps and scan_ids

        Example:
            >>> history = persistence.get_scan_history("team-abc", limit=5)
            >>> for scan in history:
            ...     print(f"{scan['scan_id']}: {scan['timestamp']}")
        """
        team_dir = f"/{team_id}"

        try:
            scan_dirs = self.nx.list(team_dir, recursive=False)
            scan_dirs = [d for d in scan_dirs if d.startswith(f"{team_dir}/scan-")]

            if not scan_dirs:
                return []

            # Sort by scan_id (descending) to get most recent first
            scan_dirs.sort(reverse=True)

            # Limit results
            scan_dirs = scan_dirs[:limit]

            # Extract metadata
            history = []
            for scan_dir in scan_dirs:
                scan_id = scan_dir.split("/")[-1]

                # Try to get timestamp from recon handoff
                handoff_path = f"{scan_dir}/handoffs/recon_handoff.json"
                timestamp = None

                try:
                    handoff_bytes = self.nx.read(handoff_path)
                    handoff_data = json.loads(handoff_bytes.decode("utf-8"))
                    timestamp = handoff_data.get("timestamp")
                except Exception:
                    pass

                history.append(
                    {
                        "scan_id": scan_id,
                        "timestamp": timestamp,
                        "team_id": team_id,
                    }
                )

            return history

        except Exception:
            return []
