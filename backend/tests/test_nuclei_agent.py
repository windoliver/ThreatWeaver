"""
Unit tests for NucleiAgent.

Tests the Nuclei agent with mocked E2B sandbox and Nexus backend.
All external dependencies are mocked for fast, isolated testing.

Run:
    pytest tests/test_nuclei_agent.py -v
"""

import json
import pytest
from unittest.mock import Mock, MagicMock

from src.agents.assessment.nuclei_agent import NucleiAgent, NucleiError, NucleiFinding


@pytest.fixture
def mock_sandbox():
    """Mock E2B sandbox for testing."""
    sandbox = Mock()
    # Mock the commands.run API (E2B SDK structure)
    sandbox.commands = Mock()
    sandbox.commands.run = Mock()
    sandbox.kill = Mock()
    return sandbox


@pytest.fixture
def mock_backend():
    """Mock Nexus backend for testing."""
    backend = Mock()
    backend.write = Mock(return_value=Mock(error=None, path="/test/path"))
    backend.read = Mock(return_value="")
    return backend


@pytest.fixture
def agent(mock_sandbox, mock_backend):
    """Create NucleiAgent with mocked dependencies."""
    agent = NucleiAgent(
        scan_id="test-scan-123",
        team_id="test-team-abc",
        nexus_backend=mock_backend,
        sandbox=mock_sandbox
    )
    # Mark that we own the sandbox so cleanup will work in tests
    agent._owns_sandbox = True
    return agent


@pytest.fixture
def sample_nuclei_jsonl():
    """Sample Nuclei JSONL output."""
    return '''{"template-id":"CVE-2021-12345","info":{"name":"Test Vulnerability","severity":"high","description":"Test description","classification":{"cvss-score":7.5,"cve-id":["CVE-2021-12345"]}},"host":"https://example.com","matched-at":"https://example.com/admin","type":"http"}
{"template-id":"exposed-panel","info":{"name":"Exposed Admin Panel","severity":"medium","description":"Admin panel exposed"},"host":"https://example.com","matched-at":"https://example.com/admin","type":"http"}
{"template-id":"info-leak","info":{"name":"Information Disclosure","severity":"low"},"host":"https://example.com","matched-at":"https://example.com/info","type":"http"}'''


class TestNucleiAgentExecution:
    """Test main execution workflow."""

    def test_execute_success(self, agent, mock_sandbox, sample_nuclei_jsonl):
        """Test successful vulnerability scanning."""
        # Arrange
        mock_update = Mock(exit_code=0, stdout="", stderr="")
        mock_scan = Mock(
            exit_code=0,
            stdout=sample_nuclei_jsonl,
            stderr=""
        )
        mock_sandbox.commands.run.side_effect = [mock_update, mock_scan]

        # Act
        findings = agent.execute(
            targets=["https://example.com"],
            severity_filter=["critical", "high", "medium"]
        )

        # Assert
        assert len(findings) == 2  # high + medium (low filtered out)
        assert findings[0].severity == "high"
        assert findings[0].template_id == "CVE-2021-12345"
        assert findings[1].severity == "medium"
        assert findings[1].template_id == "exposed-panel"

        # Verify two commands were run (update + scan)
        assert mock_sandbox.commands.run.call_count == 2

    def test_execute_no_findings(self, agent, mock_sandbox):
        """Test when no vulnerabilities are found."""
        # Arrange
        mock_update = Mock(exit_code=0, stdout="", stderr="")
        mock_scan = Mock(exit_code=0, stdout="", stderr="")
        mock_sandbox.commands.run.side_effect = [mock_update, mock_scan]

        # Act
        findings = agent.execute(
            targets=["https://example.com"],
            severity_filter=["critical", "high"]
        )

        # Assert
        assert len(findings) == 0
        assert findings == []

    def test_execute_severity_filtering(self, agent, mock_sandbox, sample_nuclei_jsonl):
        """Test severity filtering works correctly."""
        # Arrange
        mock_update = Mock(exit_code=0, stdout="", stderr="")
        mock_scan = Mock(exit_code=0, stdout=sample_nuclei_jsonl, stderr="")
        mock_sandbox.commands.run.side_effect = [mock_update, mock_scan]

        # Act - only critical and high
        findings = agent.execute(
            targets=["https://example.com"],
            severity_filter=["critical", "high"]
        )

        # Assert
        assert len(findings) == 1  # Only high severity
        assert findings[0].severity == "high"

    def test_execute_with_custom_params(self, agent, mock_sandbox):
        """Test custom parameters (rate limit, timeout)."""
        # Arrange
        mock_update = Mock(exit_code=0, stdout="", stderr="")
        mock_scan = Mock(exit_code=0, stdout="", stderr="")
        mock_sandbox.commands.run.side_effect = [mock_update, mock_scan]

        # Act
        agent.execute(
            targets=["https://example.com"],
            severity_filter=["high"],
            rate_limit=100,
            timeout=600
        )

        # Assert - check scan command (second call)
        scan_call = mock_sandbox.commands.run.call_args_list[1]
        command = scan_call[0][0]
        assert "-rate-limit 100" in command
        assert scan_call[1]['timeout'] == 600

    def test_execute_stores_results(self, agent, mock_sandbox, mock_backend, sample_nuclei_jsonl):
        """Test results are stored in Nexus workspace."""
        # Arrange
        mock_update = Mock(exit_code=0, stdout="", stderr="")
        mock_scan = Mock(exit_code=0, stdout=sample_nuclei_jsonl, stderr="")
        mock_sandbox.commands.run.side_effect = [mock_update, mock_scan]

        # Act
        agent.execute(
            targets=["https://example.com"],
            severity_filter=["high", "medium"]
        )

        # Assert
        assert mock_backend.write.call_count >= 2  # JSON + JSONL

        # Check JSON results were written
        json_calls = [call for call in mock_backend.write.call_args_list
                     if 'findings.json' in str(call)]
        assert len(json_calls) >= 1


class TestNucleiAgentValidation:
    """Test input validation."""

    def test_validate_empty_targets(self, agent):
        """Test validation fails for empty target list."""
        with pytest.raises(ValueError, match="cannot be empty"):
            agent._validate_targets([])

    def test_validate_invalid_target_type(self, agent):
        """Test validation fails for invalid target types."""
        with pytest.raises(ValueError):
            agent._validate_targets(["https://example.com", 123])

    def test_validate_missing_protocol(self, agent):
        """Test validation fails for URLs without protocol."""
        with pytest.raises(ValueError, match="must be a full URL with protocol"):
            agent._validate_targets(["example.com"])

    def test_validate_valid_targets(self, agent):
        """Test validation passes for valid URLs."""
        # Should not raise
        agent._validate_targets([
            "https://example.com",
            "http://test.com",
            "https://admin.example.com:8080/path"
        ])


class TestNucleiAgentParsing:
    """Test JSONL output parsing."""

    def test_parse_jsonl_valid(self, agent, sample_nuclei_jsonl):
        """Test parsing valid JSONL output."""
        findings = agent._parse_jsonl_output(
            sample_nuclei_jsonl,
            severity_filter=["critical", "high", "medium", "low"]
        )

        assert len(findings) == 3
        assert all(isinstance(f, NucleiFinding) for f in findings)

    def test_parse_jsonl_empty(self, agent):
        """Test parsing empty output."""
        findings = agent._parse_jsonl_output("", severity_filter=["high"])
        assert len(findings) == 0

    def test_parse_jsonl_malformed(self, agent):
        """Test parsing handles malformed JSON gracefully."""
        malformed = '''{"valid": "json"}
not valid json
{"another": "valid"}'''

        # Should skip malformed lines
        findings = agent._parse_jsonl_output(
            malformed,
            severity_filter=["info"]
        )
        # Won't match our severity filter, but should not crash
        assert isinstance(findings, list)

    def test_parse_jsonl_with_cve(self, agent):
        """Test parsing extracts CVE information."""
        jsonl_with_cve = '''{"template-id":"CVE-2021-12345","info":{"name":"Test","severity":"critical","classification":{"cvss-score":9.8,"cve-id":["CVE-2021-12345"],"cwe-id":["CWE-89"]}},"host":"https://test.com","matched-at":"https://test.com/"}'''

        findings = agent._parse_jsonl_output(jsonl_with_cve, severity_filter=["critical"])

        assert len(findings) == 1
        assert findings[0].cve_id == "CVE-2021-12345"
        assert findings[0].cwe_id == "CWE-89"
        assert findings[0].cvss_score == 9.8


class TestNucleiAgentErrors:
    """Test error handling."""

    def test_execute_timeout(self, agent, mock_sandbox):
        """Test handling of scan timeout."""
        # Arrange
        mock_update = Mock(exit_code=0, stdout="", stderr="")
        mock_sandbox.commands.run.side_effect = [
            mock_update,
            TimeoutError("Command timed out")
        ]

        # Act & Assert
        with pytest.raises(NucleiError, match="timed out"):
            agent.execute(
                targets=["https://example.com"],
                timeout=60
            )

    def test_execute_command_error(self, agent, mock_sandbox):
        """Test handling of command execution errors."""
        # Arrange
        mock_update = Mock(exit_code=0, stdout="", stderr="")
        mock_scan = Mock(exit_code=1, stdout="", stderr="ERROR: Fatal error")
        mock_sandbox.commands.run.side_effect = [mock_update, mock_scan]

        # Act & Assert
        with pytest.raises(NucleiError):
            agent.execute(targets=["https://example.com"])

    def test_cleanup_on_success(self, agent, mock_sandbox):
        """Test sandbox cleanup is called."""
        # Act
        agent.cleanup()

        # Assert
        mock_sandbox.kill.assert_called_once()

    def test_cleanup_on_failure(self, agent, mock_sandbox):
        """Test cleanup handles errors gracefully."""
        # Arrange
        mock_sandbox.kill.side_effect = Exception("Cleanup failed")

        # Act - should not raise
        agent.cleanup()

        # Assert
        mock_sandbox.kill.assert_called_once()


class TestNucleiAgentIntegration:
    """Test integration scenarios."""

    def test_full_workflow(self, agent, mock_sandbox, mock_backend, sample_nuclei_jsonl):
        """Test complete workflow from execution to storage."""
        # Arrange
        mock_update = Mock(exit_code=0, stdout="Templates updated", stderr="")
        mock_scan = Mock(exit_code=0, stdout=sample_nuclei_jsonl, stderr="")
        mock_sandbox.commands.run.side_effect = [mock_update, mock_scan]

        # Act
        findings = agent.execute(
            targets=["https://example.com", "https://test.com"],
            severity_filter=["critical", "high", "medium"],
            rate_limit=150,
            timeout=1800
        )

        # Assert
        assert len(findings) == 2  # high + medium
        assert mock_sandbox.commands.run.call_count == 2  # update + scan
        assert mock_backend.write.call_count >= 2  # JSON + JSONL

    def test_multiple_targets(self, agent, mock_sandbox):
        """Test scanning multiple targets."""
        # Arrange
        mock_update = Mock(exit_code=0, stdout="", stderr="")
        mock_scan = Mock(exit_code=0, stdout="", stderr="")
        mock_sandbox.commands.run.side_effect = [mock_update, mock_scan]

        targets = [
            "https://example.com",
            "https://test.com",
            "https://admin.example.com"
        ]

        # Act
        agent.execute(targets=targets)

        # Assert
        scan_call = mock_sandbox.commands.run.call_args_list[1]
        # Should create targets file with all URLs
        assert mock_sandbox.commands.run.call_count == 2
