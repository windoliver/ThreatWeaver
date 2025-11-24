"""
End-to-End Integration Tests for SQLMap Agent with E2B Sandbox.

These tests run SQLMap in a real E2B sandbox against safe test targets.

Note: These tests require:
- E2B_API_KEY environment variable
- Network access to test targets
- E2B template: dbe6pq4es6hqj31ybd38 (threatweaver-security)

Run with: pytest tests/integration/test_sqlmap_e2e.py -v
"""

import os
import json
import pytest
from datetime import datetime

from e2b import Sandbox

from src.agents.assessment.sqlmap_agent import (
    SQLMapAgent,
    SQLMapFinding,
    SQLMapError,
)
from src.agents.backends.nexus_backend import NexusBackend
from src.config.nexus_config import get_nexus_fs


# Skip all tests if E2B_API_KEY not set
pytestmark = pytest.mark.skipif(
    not os.environ.get("E2B_API_KEY"),
    reason="E2B_API_KEY not set - skipping E2B integration tests"
)


@pytest.fixture(scope="module")
def e2b_sandbox():
    """Create real E2B sandbox with threatweaver-security template."""
    try:
        # Create sandbox with 10 minute timeout
        sandbox = Sandbox.create(template="dbe6pq4es6hqj31ybd38", timeout=600)
        yield sandbox
        sandbox.kill()
    except Exception as e:
        pytest.skip(f"Failed to create E2B sandbox: {e}")


@pytest.fixture
def integration_workspace():
    """Create Nexus workspace for integration tests."""
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    scan_id = f"sqlmap-e2e-{timestamp}"
    team_id = "test-e2e-team"

    nexus_fs = get_nexus_fs()
    backend = NexusBackend(scan_id, team_id, nexus_fs)

    return backend, scan_id


@pytest.fixture
def sqlmap_agent(e2b_sandbox, integration_workspace):
    """Create SQLMapAgent with E2B sandbox."""
    backend, scan_id = integration_workspace

    agent = SQLMapAgent(
        scan_id=scan_id,
        team_id="test-e2e-team",
        nexus_backend=backend,
        sandbox=e2b_sandbox
    )

    return agent


@pytest.mark.integration
@pytest.mark.slow
class TestSQLMapToolAvailability:
    """Verify SQLMap is available in E2B sandbox."""

    def test_sqlmap_installed(self, e2b_sandbox):
        """Verify SQLMap is installed and accessible."""
        result = e2b_sandbox.commands.run("which sqlmap")
        assert result.exit_code == 0
        assert "sqlmap" in result.stdout
        print(f"\n✅ SQLMap found at: {result.stdout.strip()}")

    def test_sqlmap_version(self, e2b_sandbox):
        """Check SQLMap version."""
        result = e2b_sandbox.commands.run("sqlmap --version 2>&1")
        assert "sqlmap" in result.stdout.lower() or "1." in result.stdout
        print(f"\n✅ SQLMap version: {result.stdout.strip()}")

    def test_sqlmap_help(self, e2b_sandbox):
        """Verify SQLMap help works."""
        result = e2b_sandbox.commands.run("sqlmap -h 2>&1 | head -20")
        assert result.exit_code == 0
        assert "usage" in result.stdout.lower() or "options" in result.stdout.lower()
        print(f"\n✅ SQLMap help available")


@pytest.mark.integration
@pytest.mark.slow
class TestSQLMapBasicExecution:
    """Test basic SQLMap execution against safe targets."""

    def test_scan_non_vulnerable_target(self, sqlmap_agent):
        """Test scanning a target without SQL injection."""
        # scanme.nmap.org doesn't have SQL injection
        # This tests that SQLMap runs without crashing
        findings = sqlmap_agent.execute(
            target_url="http://scanme.nmap.org/?test=1",
            level=1,
            risk=1,
            timeout=120
        )

        assert isinstance(findings, list)
        # Should find 0 or minimal findings on this hardened target
        print(f"\n✅ Non-vulnerable scan completed: {len(findings)} findings")

    def test_scan_with_post_data(self, e2b_sandbox, integration_workspace):
        """Test scanning with POST data."""
        backend, scan_id = integration_workspace

        agent = SQLMapAgent(
            scan_id=scan_id + "-post",
            team_id="test-e2e-team",
            nexus_backend=backend,
            sandbox=e2b_sandbox
        )

        # Test with POST data (even if target doesn't accept it)
        findings = agent.execute(
            target_url="http://scanme.nmap.org/",
            data="username=test&password=test",
            level=1,
            risk=1,
            timeout=120
        )

        assert isinstance(findings, list)
        print(f"\n✅ POST data scan completed: {len(findings)} findings")

    def test_scan_with_cookie(self, e2b_sandbox, integration_workspace):
        """Test scanning with cookie authentication."""
        backend, scan_id = integration_workspace

        agent = SQLMapAgent(
            scan_id=scan_id + "-cookie",
            team_id="test-e2e-team",
            nexus_backend=backend,
            sandbox=e2b_sandbox
        )

        findings = agent.execute(
            target_url="http://scanme.nmap.org/?id=1",
            cookie="session=test123",
            level=1,
            risk=1,
            timeout=120
        )

        assert isinstance(findings, list)
        print(f"\n✅ Cookie-authenticated scan completed: {len(findings)} findings")


@pytest.mark.integration
@pytest.mark.slow
class TestSQLMapLevelsAndRisks:
    """Test different SQLMap level and risk settings."""

    def test_level_1_basic(self, e2b_sandbox, integration_workspace):
        """Test level 1 (basic) scan."""
        backend, scan_id = integration_workspace

        agent = SQLMapAgent(
            scan_id=scan_id + "-level1",
            team_id="test-e2e-team",
            nexus_backend=backend,
            sandbox=e2b_sandbox
        )

        findings = agent.execute(
            target_url="http://scanme.nmap.org/?id=1",
            level=1,
            risk=1,
            timeout=90
        )

        assert isinstance(findings, list)
        print(f"\n✅ Level 1 scan: {len(findings)} findings")

    def test_level_2_standard(self, e2b_sandbox, integration_workspace):
        """Test level 2 (standard) scan."""
        backend, scan_id = integration_workspace

        agent = SQLMapAgent(
            scan_id=scan_id + "-level2",
            team_id="test-e2e-team",
            nexus_backend=backend,
            sandbox=e2b_sandbox
        )

        findings = agent.execute(
            target_url="http://scanme.nmap.org/?id=1",
            level=2,
            risk=1,
            timeout=120
        )

        assert isinstance(findings, list)
        print(f"\n✅ Level 2 scan: {len(findings)} findings")

    def test_risk_1_safe(self, e2b_sandbox, integration_workspace):
        """Test risk 1 (safe) scan."""
        backend, scan_id = integration_workspace

        agent = SQLMapAgent(
            scan_id=scan_id + "-risk1",
            team_id="test-e2e-team",
            nexus_backend=backend,
            sandbox=e2b_sandbox
        )

        findings = agent.execute(
            target_url="http://scanme.nmap.org/?id=1",
            level=1,
            risk=1,
            timeout=90
        )

        assert isinstance(findings, list)
        print(f"\n✅ Risk 1 (safe) scan: {len(findings)} findings")


@pytest.mark.integration
@pytest.mark.slow
class TestSQLMapResultsStorage:
    """Test results storage in Nexus workspace."""

    def test_results_stored_in_nexus(self, sqlmap_agent, integration_workspace):
        """Verify results are stored in Nexus workspace."""
        backend, scan_id = integration_workspace

        findings = sqlmap_agent.execute(
            target_url="http://scanme.nmap.org/?id=1",
            level=1,
            risk=1,
            timeout=90
        )

        # Read results from workspace
        json_path = "/assessment/sqlmap/findings.json"
        content = backend.read(json_path)

        assert content is not None
        assert not content.startswith("Error:")

        # Parse and verify structure
        # Remove line numbers if present
        lines = content.split("\n")
        clean_lines = []
        for line in lines:
            if "→" in line:
                clean_lines.append(line.split("→", 1)[1])
            else:
                clean_lines.append(line)

        json_content = "\n".join(clean_lines)
        data = json.loads(json_content)

        assert "target_url" in data
        assert "vulnerable" in data
        assert "findings" in data
        assert data["tool"] == "sqlmap"

        print(f"\n✅ Results stored in Nexus: {json_path}")
        print(f"   Vulnerable: {data['vulnerable']}")
        print(f"   Findings: {data['findings_count']}")

    def test_raw_output_stored(self, e2b_sandbox, integration_workspace):
        """Verify raw SQLMap output is stored."""
        backend, scan_id = integration_workspace

        agent = SQLMapAgent(
            scan_id=scan_id + "-raw",
            team_id="test-e2e-team",
            nexus_backend=backend,
            sandbox=e2b_sandbox
        )

        agent.execute(
            target_url="http://scanme.nmap.org/?id=1",
            level=1,
            risk=1,
            timeout=90
        )

        # Read raw output
        raw_path = "/assessment/sqlmap/raw_output.txt"
        content = backend.read(raw_path)

        assert content is not None
        # Raw output should contain SQLMap markers
        print(f"\n✅ Raw output stored: {raw_path}")


@pytest.mark.integration
@pytest.mark.slow
class TestSQLMapErrorHandling:
    """Test error handling scenarios."""

    def test_invalid_target_rejected(self, e2b_sandbox, integration_workspace):
        """Test that invalid targets are rejected."""
        backend, scan_id = integration_workspace

        agent = SQLMapAgent(
            scan_id=scan_id + "-invalid",
            team_id="test-e2e-team",
            nexus_backend=backend,
            sandbox=e2b_sandbox
        )

        with pytest.raises(ValueError, match="must be a full URL"):
            agent.execute(
                target_url="not-a-valid-url",
                timeout=60
            )

        print("\n✅ Invalid target properly rejected")

    def test_empty_target_rejected(self, e2b_sandbox, integration_workspace):
        """Test that empty targets are rejected."""
        backend, scan_id = integration_workspace

        agent = SQLMapAgent(
            scan_id=scan_id + "-empty",
            team_id="test-e2e-team",
            nexus_backend=backend,
            sandbox=e2b_sandbox
        )

        with pytest.raises(ValueError, match="cannot be empty"):
            agent.execute(
                target_url="",
                timeout=60
            )

        print("\n✅ Empty target properly rejected")

    def test_timeout_enforcement(self, e2b_sandbox, integration_workspace):
        """Test that very short timeout is handled."""
        backend, scan_id = integration_workspace

        agent = SQLMapAgent(
            scan_id=scan_id + "-timeout",
            team_id="test-e2e-team",
            nexus_backend=backend,
            sandbox=e2b_sandbox
        )

        # Very short timeout - might complete or timeout
        try:
            findings = agent.execute(
                target_url="http://scanme.nmap.org/?id=1",
                level=1,
                risk=1,
                timeout=30  # Very short
            )
            print(f"\n✅ Scan completed within timeout: {len(findings)} findings")
        except SQLMapError as e:
            error_msg = str(e).lower()
            assert "timeout" in error_msg or "timed out" in error_msg or "sandbox" in error_msg
            print("\n✅ Timeout properly enforced")


@pytest.mark.integration
class TestSQLMapQuickValidation:
    """Quick validation tests for CI/CD."""

    def test_quick_scan(self, e2b_sandbox, integration_workspace):
        """Quick scan to validate SQLMap works."""
        backend, scan_id = integration_workspace

        agent = SQLMapAgent(
            scan_id=scan_id + "-quick",
            team_id="test-e2e-team",
            nexus_backend=backend,
            sandbox=e2b_sandbox
        )

        # Quick scan with minimal settings
        findings = agent.execute(
            target_url="http://scanme.nmap.org/?test=1",
            level=1,
            risk=1,
            timeout=60,
            enumerate_dbs=False  # Faster without enumeration
        )

        assert isinstance(findings, list)
        print(f"\n✅ Quick validation passed: {len(findings)} findings")
