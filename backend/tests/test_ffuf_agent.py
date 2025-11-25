"""
Unit tests for ffuf Agent.

Tests use mocks to avoid E2B sandbox dependencies.
For E2E integration tests, see tests/integration/test_ffuf_e2e.py
"""

import pytest
import json
from unittest.mock import Mock, MagicMock, patch

from src.agents.recon.ffuf_agent import (
    FfufAgent,
    FfufFinding,
    FfufError,
    WordlistType,
)


@pytest.fixture
def mock_backend():
    """Create a mock NexusBackend."""
    backend = Mock()
    backend.write = Mock(return_value=Mock(error=None))
    backend.read = Mock(return_value="")
    backend.edit = Mock(return_value=Mock(error=None))
    return backend


@pytest.fixture
def mock_sandbox():
    """Create a mock E2B Sandbox."""
    sandbox = Mock()
    sandbox.commands = Mock()
    sandbox.files = Mock()
    sandbox.kill = Mock()
    return sandbox


class TestFfufFinding:
    """Test FfufFinding data model."""

    def test_finding_creation(self):
        """Test creating a FfufFinding."""
        finding = FfufFinding(
            url="https://example.com/admin",
            path="/admin",
            status_code=200,
            content_length=1234,
            content_type="text/html",
            words=150,
            lines=25,
        )

        assert finding.url == "https://example.com/admin"
        assert finding.path == "/admin"
        assert finding.status_code == 200
        assert finding.content_length == 1234

    def test_finding_with_redirect(self):
        """Test FfufFinding with redirect location."""
        finding = FfufFinding(
            url="https://example.com/old",
            path="/old",
            status_code=301,
            content_length=0,
            redirect_location="https://example.com/new",
        )

        assert finding.status_code == 301
        assert finding.redirect_location == "https://example.com/new"

    def test_finding_model_dump(self):
        """Test FfufFinding serialization."""
        finding = FfufFinding(
            url="https://example.com/test",
            path="/test",
            status_code=200,
            content_length=500,
        )

        data = finding.model_dump()
        assert "url" in data
        assert "path" in data
        assert "status_code" in data
        assert data["status_code"] == 200


class TestFfufAgentInit:
    """Test FfufAgent initialization."""

    @patch("src.agents.recon.ffuf_agent.Sandbox")
    def test_creates_sandbox_if_not_provided(self, mock_sandbox_class, mock_backend):
        """Test that agent creates its own sandbox if not provided."""
        mock_sandbox_instance = Mock()
        mock_sandbox_class.create.return_value = mock_sandbox_instance

        agent = FfufAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
        )

        mock_sandbox_class.create.assert_called_once()
        assert agent._owns_sandbox is True

    def test_uses_provided_sandbox(self, mock_backend, mock_sandbox):
        """Test that agent uses provided sandbox."""
        agent = FfufAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        assert agent.sandbox == mock_sandbox
        assert agent._owns_sandbox is False


class TestFfufAgentValidation:
    """Test URL validation."""

    def test_validate_url_valid_http(self, mock_backend, mock_sandbox):
        """Test valid HTTP URL passes validation."""
        agent = FfufAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        # Should not raise
        agent._validate_url("http://example.com")
        agent._validate_url("https://example.com")
        agent._validate_url("https://example.com:8080")
        agent._validate_url("https://example.com/path")

    def test_validate_url_invalid(self, mock_backend, mock_sandbox):
        """Test invalid URLs fail validation."""
        agent = FfufAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        with pytest.raises(ValueError):
            agent._validate_url("example.com")  # Missing scheme

        with pytest.raises(ValueError):
            agent._validate_url("ftp://example.com")  # Wrong scheme


class TestFfufAgentParsing:
    """Test ffuf output parsing."""

    def test_parse_empty_output(self, mock_backend, mock_sandbox):
        """Test parsing empty results."""
        agent = FfufAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        findings = agent._parse_output('{"results": []}', "https://example.com")
        assert findings == []

    def test_parse_valid_output(self, mock_backend, mock_sandbox):
        """Test parsing valid ffuf output."""
        agent = FfufAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        ffuf_output = json.dumps({
            "results": [
                {
                    "url": "https://example.com/admin",
                    "input": {"FUZZ": "admin"},
                    "status": 200,
                    "length": 1500,
                    "content-type": "text/html",
                    "words": 200,
                    "lines": 50,
                },
                {
                    "url": "https://example.com/backup",
                    "input": {"FUZZ": "backup"},
                    "status": 403,
                    "length": 300,
                    "words": 10,
                    "lines": 5,
                }
            ]
        })

        findings = agent._parse_output(ffuf_output, "https://example.com")

        assert len(findings) == 2
        assert findings[0].path == "/admin"
        assert findings[0].status_code == 200
        assert findings[0].content_length == 1500
        assert findings[1].path == "/backup"
        assert findings[1].status_code == 403

    def test_parse_invalid_json(self, mock_backend, mock_sandbox):
        """Test parsing invalid JSON returns empty list."""
        agent = FfufAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        findings = agent._parse_output("not valid json", "https://example.com")
        assert findings == []


class TestFfufAgentExecution:
    """Test ffuf execution."""

    def test_execute_success(self, mock_backend, mock_sandbox):
        """Test successful ffuf execution."""
        # Setup mock sandbox responses
        mock_sandbox.commands.run.side_effect = [
            Mock(exit_code=0, stdout="/usr/bin/ffuf"),  # which ffuf
            Mock(exit_code=0, stdout=""),  # wordlist check
            Mock(exit_code=0, stdout=""),  # ffuf execution
        ]

        ffuf_output = json.dumps({
            "results": [
                {
                    "url": "https://example.com/admin",
                    "input": {"FUZZ": "admin"},
                    "status": 200,
                    "length": 1500,
                    "words": 200,
                    "lines": 50,
                }
            ]
        })
        mock_sandbox.files.read.return_value = ffuf_output

        agent = FfufAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        findings = agent.execute("https://example.com")

        assert len(findings) == 1
        assert findings[0].path == "/admin"
        mock_backend.write.assert_called()

    def test_execute_with_extensions(self, mock_backend, mock_sandbox):
        """Test ffuf execution with file extensions."""
        mock_sandbox.commands.run.side_effect = [
            Mock(exit_code=0, stdout="/usr/bin/ffuf"),
            Mock(exit_code=0, stdout=""),
            Mock(exit_code=0, stdout=""),
        ]
        mock_sandbox.files.read.return_value = '{"results": []}'

        agent = FfufAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        agent.execute(
            "https://example.com",
            extensions=[".php", ".bak", ".old"],
        )

        # Verify ffuf was called with extensions
        call_args = mock_sandbox.commands.run.call_args_list[-1]
        command = call_args[0][0]
        assert "-e" in command


class TestFfufAgentCleanup:
    """Test cleanup behavior."""

    def test_cleanup_kills_owned_sandbox(self, mock_backend):
        """Test cleanup kills sandbox when agent owns it."""
        with patch("src.agents.recon.ffuf_agent.Sandbox") as mock_sandbox_class:
            mock_sandbox_instance = Mock()
            mock_sandbox_class.create.return_value = mock_sandbox_instance

            agent = FfufAgent(
                scan_id="test-scan",
                team_id="test-team",
                nexus_backend=mock_backend,
            )

            agent.cleanup()

            mock_sandbox_instance.kill.assert_called_once()

    def test_cleanup_does_not_kill_provided_sandbox(self, mock_backend, mock_sandbox):
        """Test cleanup doesn't kill sandbox when provided externally."""
        agent = FfufAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        agent.cleanup()

        mock_sandbox.kill.assert_not_called()


class TestWordlistType:
    """Test wordlist type enum."""

    def test_wordlist_values(self):
        """Test wordlist enum values."""
        assert WordlistType.COMMON.value == "common"
        assert WordlistType.BIG.value == "big"
        assert WordlistType.RAFT_DIRS.value == "raft-dirs"
