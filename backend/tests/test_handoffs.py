"""
Tests for the hybrid handoff system.

This module tests:
- TypedDict schemas
- HandoffPersistence (save/load)
- DiffDetector (subdomain, vulnerability, technology diffs)
- Handoff analysis nodes (recon→assessment, assessment→exploit)

Test Strategy:
- Use in-memory Nexus for fast tests
- Test both first-scan and subsequent-scan scenarios
- Verify adaptive workflow decisions
- Measure performance (3% improvement goal)
"""

import json
from datetime import datetime

import pytest
from nexus import LocalBackend, NexusFS

from src.agents.handoffs.diff import DiffDetector, HandoffDiff
from src.agents.handoffs.nodes import (
    assessment_to_exploit_handoff,
    finalize_scan,
    recon_to_assessment_handoff,
)
from src.agents.handoffs.persistence import HandoffPersistence
from src.agents.handoffs.schemas import (
    AssessmentHandoff,
    ReconHandoff,
    ScanState,
)


@pytest.fixture
def nexus_fs(tmp_path):
    """Create in-memory NexusFS for testing."""
    backend = LocalBackend(str(tmp_path))
    return NexusFS(backend)


@pytest.fixture
def sample_recon_handoff() -> ReconHandoff:
    """Sample recon handoff data."""
    return ReconHandoff(
        subdomains=["api.target.com", "admin.target.com", "blog.target.com"],
        live_hosts=[
            {"url": "https://api.target.com", "status_code": 200},
            {"url": "https://admin.target.com", "status_code": 403},
        ],
        high_value_targets=["admin.target.com"],
        open_ports=[
            {"host": "1.2.3.4", "port": 443, "service": "https"},
            {"host": "1.2.3.4", "port": 22, "service": "ssh"},
        ],
        technologies=["nginx", "wordpress", "php"],
        metadata={"tool_version": "v1.0", "scan_duration": 120},
    )


@pytest.fixture
def sample_assessment_handoff() -> AssessmentHandoff:
    """Sample assessment handoff data."""
    return AssessmentHandoff(
        vulnerabilities=[
            {"template": "cve-2023-1234", "severity": "critical", "url": "https://api.target.com"},
            {"template": "cve-2023-5678", "severity": "high", "url": "https://admin.target.com"},
        ],
        critical_findings=["SQL injection in /api/login", "Exposed admin panel"],
        suggested_exploits=["Use SQLMap for /api/login", "Try default credentials on admin panel"],
        attack_surface_score=75,
        metadata={"tool_version": "v1.0", "scan_duration": 300},
    )


class TestHandoffPersistence:
    """Test HandoffPersistence save/load operations."""

    def test_save_and_load_recon_handoff(self, nexus_fs, sample_recon_handoff):
        """Test saving and loading recon handoff."""
        persistence = HandoffPersistence(nexus_fs)

        # Save handoff
        persistence.save_recon_handoff(
            scan_id="scan-20251119-001",
            team_id="team-abc",
            handoff=sample_recon_handoff,
        )

        # Load handoff
        loaded = persistence.load_previous_recon(
            team_id="team-abc",
            target="target.com",
        )

        # Verify data
        assert loaded is not None
        assert loaded["subdomains"] == sample_recon_handoff["subdomains"]
        assert loaded["technologies"] == sample_recon_handoff["technologies"]
        assert len(loaded["live_hosts"]) == 2

    def test_save_and_load_assessment_handoff(self, nexus_fs, sample_assessment_handoff):
        """Test saving and loading assessment handoff."""
        persistence = HandoffPersistence(nexus_fs)

        # Save handoff
        persistence.save_assessment_handoff(
            scan_id="scan-20251119-001",
            team_id="team-abc",
            handoff=sample_assessment_handoff,
        )

        # Load handoff
        loaded = persistence.load_previous_assessment(
            team_id="team-abc",
            target="target.com",
        )

        # Verify data
        assert loaded is not None
        assert len(loaded["vulnerabilities"]) == 2
        assert loaded["critical_findings"] == sample_assessment_handoff["critical_findings"]
        assert loaded["attack_surface_score"] == 75

    def test_load_previous_when_none_exists(self, nexus_fs):
        """Test loading previous handoff when none exists (first scan)."""
        persistence = HandoffPersistence(nexus_fs)

        loaded = persistence.load_previous_recon(
            team_id="team-abc",
            target="target.com",
        )

        assert loaded is None  # First scan

    def test_load_most_recent_scan(self, nexus_fs, sample_recon_handoff):
        """Test loading the most recent scan (not oldest)."""
        persistence = HandoffPersistence(nexus_fs)

        # Save three scans
        for i in range(3):
            scan_id = f"scan-2025111{i}-00{i}"
            handoff = sample_recon_handoff.copy()
            handoff["subdomains"] = [f"subdomain{i}.target.com"]

            persistence.save_recon_handoff(
                scan_id=scan_id,
                team_id="team-abc",
                handoff=handoff,
            )

        # Load most recent
        loaded = persistence.load_previous_recon(
            team_id="team-abc",
            target="target.com",
        )

        # Should get the last scan (scan-20251112-002)
        assert loaded is not None
        assert loaded["subdomains"] == ["subdomain2.target.com"]

    def test_get_scan_history(self, nexus_fs, sample_recon_handoff):
        """Test getting scan history."""
        persistence = HandoffPersistence(nexus_fs)

        # Save three scans
        for i in range(3):
            scan_id = f"scan-2025111{i}-00{i}"
            persistence.save_recon_handoff(
                scan_id=scan_id,
                team_id="team-abc",
                handoff=sample_recon_handoff,
            )

        # Get history
        history = persistence.get_scan_history("team-abc", limit=10)

        # Verify we got at least the 3 scans we created
        assert len(history) >= 3

        # Extract scan IDs
        scan_ids = [h["scan_id"] for h in history]

        # Verify our scans are present and in correct order (most recent first)
        assert "scan-20251112-002" in scan_ids
        assert "scan-20251111-001" in scan_ids
        assert "scan-20251110-000" in scan_ids

        # Verify ordering of our scans
        idx_002 = scan_ids.index("scan-20251112-002")
        idx_001 = scan_ids.index("scan-20251111-001")
        idx_000 = scan_ids.index("scan-20251110-000")
        assert idx_002 < idx_001 < idx_000  # Most recent first


class TestDiffDetector:
    """Test DiffDetector for cross-scan comparisons."""

    def test_diff_subdomains_with_new_items(self):
        """Test subdomain diff when new subdomains are found."""
        current = ReconHandoff(
            subdomains=["api.target.com", "admin.target.com", "new.target.com"],
            live_hosts=[],
            high_value_targets=[],
            open_ports=[],
            technologies=[],
            metadata={},
        )

        previous = ReconHandoff(
            subdomains=["api.target.com", "admin.target.com"],
            live_hosts=[],
            high_value_targets=[],
            open_ports=[],
            technologies=[],
            metadata={},
        )

        diff = DiffDetector.diff_subdomains(current, previous)

        assert diff["new_items"] == ["new.target.com"]
        assert diff["removed_items"] == []
        assert len(diff["unchanged_items"]) == 2
        assert diff["growth_percentage"] == 50.0  # 1 new out of 2 = 50% growth

    def test_diff_subdomains_with_removed_items(self):
        """Test subdomain diff when subdomains disappear."""
        current = ReconHandoff(
            subdomains=["api.target.com"],
            live_hosts=[],
            high_value_targets=[],
            open_ports=[],
            technologies=[],
            metadata={},
        )

        previous = ReconHandoff(
            subdomains=["api.target.com", "admin.target.com"],
            live_hosts=[],
            high_value_targets=[],
            open_ports=[],
            technologies=[],
            metadata={},
        )

        diff = DiffDetector.diff_subdomains(current, previous)

        assert diff["new_items"] == []
        assert diff["removed_items"] == ["admin.target.com"]
        assert diff["growth_percentage"] == -50.0  # Negative growth

    def test_diff_subdomains_recommend_deep_osint(self):
        """Test that >20 new subdomains triggers deep OSINT recommendation."""
        current = ReconHandoff(
            subdomains=[f"sub{i}.target.com" for i in range(30)],
            live_hosts=[],
            high_value_targets=[],
            open_ports=[],
            technologies=[],
            metadata={},
        )

        previous = ReconHandoff(
            subdomains=["api.target.com"],
            live_hosts=[],
            high_value_targets=[],
            open_ports=[],
            technologies=[],
            metadata={},
        )

        diff = DiffDetector.diff_subdomains(current, previous)

        assert len(diff["new_items"]) == 30  # 30 new subdomains (no overlap)
        assert diff["recommendation"] == "RECOMMEND_DEEP_OSINT"

    def test_diff_vulnerabilities_new_vulns(self):
        """Test vulnerability diff when new vulns are found."""
        current = AssessmentHandoff(
            vulnerabilities=[
                {"template": "cve-2023-1234", "severity": "critical"},
                {"template": "cve-2023-5678", "severity": "high"},
            ],
            critical_findings=[],
            suggested_exploits=[],
            attack_surface_score=0,
            metadata={},
        )

        previous = AssessmentHandoff(
            vulnerabilities=[
                {"template": "cve-2023-1234", "severity": "critical"},
            ],
            critical_findings=[],
            suggested_exploits=[],
            attack_surface_score=0,
            metadata={},
        )

        diff = DiffDetector.diff_vulnerabilities(current, previous)

        assert diff["new_items"] == ["cve-2023-5678"]
        assert diff["removed_items"] == []  # No fixed vulns
        assert diff["recommendation"] == "SECURITY_DEGRADED"

    def test_diff_vulnerabilities_fixed_vulns(self):
        """Test vulnerability diff when vulns are fixed."""
        current = AssessmentHandoff(
            vulnerabilities=[],
            critical_findings=[],
            suggested_exploits=[],
            attack_surface_score=0,
            metadata={},
        )

        previous = AssessmentHandoff(
            vulnerabilities=[
                {"template": "cve-2023-1234", "severity": "critical"},
            ],
            critical_findings=[],
            suggested_exploits=[],
            attack_surface_score=0,
            metadata={},
        )

        diff = DiffDetector.diff_vulnerabilities(current, previous)

        assert diff["new_items"] == []
        assert diff["removed_items"] == ["cve-2023-1234"]  # Fixed!
        assert diff["recommendation"] == "SECURITY_IMPROVED"

    def test_diff_technologies(self):
        """Test technology diff detection."""
        current = ReconHandoff(
            subdomains=[],
            live_hosts=[],
            high_value_targets=[],
            open_ports=[],
            technologies=["nginx", "wordpress", "php"],
            metadata={},
        )

        previous = ReconHandoff(
            subdomains=[],
            live_hosts=[],
            high_value_targets=[],
            open_ports=[],
            technologies=["nginx"],
            metadata={},
        )

        diff = DiffDetector.diff_technologies(current, previous)

        assert "wordpress" in diff["new_items"]
        assert "php" in diff["new_items"]
        assert diff["recommendation"] == "RUN_CMS_SCANNERS"

    def test_summarize_diff(self):
        """Test diff summary generation."""
        diff = HandoffDiff(
            new_items=["sub1.target.com", "sub2.target.com"],
            removed_items=[],
            unchanged_items=["api.target.com"],
            growth_percentage=66.67,
            recommendation="MODERATE_GROWTH",
        )

        summary = DiffDetector.summarize_diff(diff, "subdomains")

        assert "2 new subdomains" in summary
        assert "+66.67% growth" in summary
        assert "MODERATE_GROWTH" in summary


class TestHandoffNodes:
    """Test handoff analysis nodes for LangGraph workflows."""

    def test_recon_to_assessment_first_scan(self, nexus_fs, sample_recon_handoff):
        """Test recon→assessment handoff on first scan (no historical data)."""
        state = ScanState(
            scan_id="scan-20251119-001",
            team_id="team-abc",
            target="target.com",
            recon_handoff=sample_recon_handoff,
            assessment_handoff=None,
            previous_recon=None,
            previous_assessment=None,
            new_subdomains=[],
            removed_subdomains=[],
            new_vulnerabilities=[],
            fixed_vulnerabilities=[],
            next_step="",
            metadata={},
        )

        # Run handoff node
        updated_state = recon_to_assessment_handoff(state, nexus_fs)

        # Verify
        assert updated_state["next_step"] == "vuln_scan"  # First scan → vuln scan
        assert updated_state["new_subdomains"] == sample_recon_handoff["subdomains"]
        assert updated_state["removed_subdomains"] == []

    def test_recon_to_assessment_with_significant_growth(self, nexus_fs, sample_recon_handoff):
        """Test recon→assessment handoff with >20 new subdomains (triggers deep OSINT)."""
        persistence = HandoffPersistence(nexus_fs)

        # Save previous scan (small)
        previous = ReconHandoff(
            subdomains=["api.target.com"],
            live_hosts=[],
            high_value_targets=[],
            open_ports=[],
            technologies=[],
            metadata={},
        )

        persistence.save_recon_handoff(
            scan_id="scan-20251118-001",
            team_id="team-abc",
            handoff=previous,
        )

        # Current scan (large)
        current = ReconHandoff(
            subdomains=[f"sub{i}.target.com" for i in range(25)],
            live_hosts=[],
            high_value_targets=[],
            open_ports=[],
            technologies=[],
            metadata={},
        )

        state = ScanState(
            scan_id="scan-20251119-001",
            team_id="team-abc",
            target="target.com",
            recon_handoff=current,
            assessment_handoff=None,
            previous_recon=None,
            previous_assessment=None,
            new_subdomains=[],
            removed_subdomains=[],
            new_vulnerabilities=[],
            fixed_vulnerabilities=[],
            next_step="",
            metadata={},
        )

        # Run handoff node
        updated_state = recon_to_assessment_handoff(state, nexus_fs)

        # Verify deep OSINT triggered
        assert updated_state["next_step"] == "deep_osint"
        assert len(updated_state["new_subdomains"]) == 25  # 25 new subdomains (no overlap)
        assert "Running Amass" in updated_state["metadata"]["reason"]

    def test_recon_to_assessment_no_changes(self, nexus_fs, sample_recon_handoff):
        """Test recon→assessment handoff when no changes detected (skip scans)."""
        persistence = HandoffPersistence(nexus_fs)

        # Save previous scan
        persistence.save_recon_handoff(
            scan_id="scan-20251118-001",
            team_id="team-abc",
            handoff=sample_recon_handoff,
        )

        # Current scan (identical)
        state = ScanState(
            scan_id="scan-20251119-001",
            team_id="team-abc",
            target="target.com",
            recon_handoff=sample_recon_handoff,
            assessment_handoff=None,
            previous_recon=None,
            previous_assessment=None,
            new_subdomains=[],
            removed_subdomains=[],
            new_vulnerabilities=[],
            fixed_vulnerabilities=[],
            next_step="",
            metadata={},
        )

        # Run handoff node
        updated_state = recon_to_assessment_handoff(state, nexus_fs)

        # Verify skip to report
        assert updated_state["next_step"] == "report"
        assert len(updated_state["new_subdomains"]) == 0
        assert "No new subdomains" in updated_state["metadata"]["reason"]

    def test_assessment_to_exploit_first_scan(self, nexus_fs, sample_assessment_handoff):
        """Test assessment→exploit handoff on first scan."""
        state = ScanState(
            scan_id="scan-20251119-001",
            team_id="team-abc",
            target="target.com",
            recon_handoff=None,
            assessment_handoff=sample_assessment_handoff,
            previous_recon=None,
            previous_assessment=None,
            new_subdomains=[],
            removed_subdomains=[],
            new_vulnerabilities=[],
            fixed_vulnerabilities=[],
            next_step="",
            metadata={},
        )

        # Run handoff node
        updated_state = assessment_to_exploit_handoff(state, nexus_fs)

        # Verify exploit triggered (critical findings exist)
        assert updated_state["next_step"] == "exploit"
        assert len(updated_state["new_vulnerabilities"]) == 2

    def test_assessment_to_exploit_security_improved(self, nexus_fs):
        """Test assessment→exploit handoff when vulnerabilities are fixed."""
        persistence = HandoffPersistence(nexus_fs)

        # Save previous scan (with vulnerabilities)
        previous = AssessmentHandoff(
            vulnerabilities=[
                {"template": "cve-2023-1234", "severity": "critical"},
            ],
            critical_findings=["SQL injection"],
            suggested_exploits=[],
            attack_surface_score=50,
            metadata={},
        )

        persistence.save_assessment_handoff(
            scan_id="scan-20251118-001",
            team_id="team-abc",
            handoff=previous,
        )

        # Current scan (no vulnerabilities - all fixed!)
        current = AssessmentHandoff(
            vulnerabilities=[],
            critical_findings=[],
            suggested_exploits=[],
            attack_surface_score=10,
            metadata={},
        )

        state = ScanState(
            scan_id="scan-20251119-001",
            team_id="team-abc",
            target="target.com",
            recon_handoff=None,
            assessment_handoff=current,
            previous_recon=None,
            previous_assessment=None,
            new_subdomains=[],
            removed_subdomains=[],
            new_vulnerabilities=[],
            fixed_vulnerabilities=[],
            next_step="",
            metadata={},
        )

        # Run handoff node
        updated_state = assessment_to_exploit_handoff(state, nexus_fs)

        # Verify report triggered (security improved)
        assert updated_state["next_step"] == "report"
        assert len(updated_state["fixed_vulnerabilities"]) == 1
        assert "Security improved" in updated_state["metadata"]["reason"]

    def test_finalize_scan(self, nexus_fs, sample_recon_handoff, sample_assessment_handoff):
        """Test finalize_scan persists handoffs to Nexus."""
        state = ScanState(
            scan_id="scan-20251119-001",
            team_id="team-abc",
            target="target.com",
            recon_handoff=sample_recon_handoff,
            assessment_handoff=sample_assessment_handoff,
            previous_recon=None,
            previous_assessment=None,
            new_subdomains=[],
            removed_subdomains=[],
            new_vulnerabilities=[],
            fixed_vulnerabilities=[],
            next_step="",
            metadata={},
        )

        # Run finalize node
        updated_state = finalize_scan(state, nexus_fs)

        # Verify persistence metadata
        assert updated_state["metadata"]["handoffs_persisted"] is True
        assert "team-abc/scan-20251119-001/handoffs" in updated_state["metadata"]["handoff_location"]

        # Verify files were actually written
        persistence = HandoffPersistence(nexus_fs)

        loaded_recon = persistence.load_previous_recon("team-abc", "target.com")
        loaded_assessment = persistence.load_previous_assessment("team-abc", "target.com")

        assert loaded_recon is not None
        assert loaded_assessment is not None
        assert loaded_recon["subdomains"] == sample_recon_handoff["subdomains"]
        assert loaded_assessment["attack_surface_score"] == 75
