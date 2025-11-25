"""
Unit tests for XSStrike Agent.

Tests use mocks to avoid E2B sandbox dependencies.
For E2E integration tests, see tests/integration/test_xsstrike_e2e.py
"""

import pytest
import json
from unittest.mock import Mock, MagicMock, patch

from src.agents.assessment.xsstrike_agent import (
    XSStrikeAgent,
    XSSFinding,
    XSSStrikeError,
    XSSType,
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


class TestXSSFinding:
    """Test XSSFinding data model."""

    def test_finding_creation_vulnerable(self):
        """Test creating a XSSFinding with vulnerability."""
        finding = XSSFinding(
            target_url="https://example.com/search?q=test",
            vulnerable=True,
            xss_type="reflected",
            parameter="q",
            payload="<script>alert(1)</script>",
            confidence="high",
        )

        assert finding.target_url == "https://example.com/search?q=test"
        assert finding.vulnerable is True
        assert finding.xss_type == "reflected"
        assert finding.parameter == "q"
        assert finding.payload == "<script>alert(1)</script>"

    def test_finding_creation_not_vulnerable(self):
        """Test creating a XSSFinding with no vulnerability."""
        finding = XSSFinding(
            target_url="https://example.com/search?q=test",
            vulnerable=False,
            confidence="high",
        )

        assert finding.target_url == "https://example.com/search?q=test"
        assert finding.vulnerable is False
        assert finding.xss_type is None
        assert finding.parameter is None

    def test_finding_with_waf(self):
        """Test XSSFinding with WAF detection."""
        finding = XSSFinding(
            target_url="https://example.com/search?q=test",
            vulnerable=True,
            xss_type="reflected",
            waf_detected="Cloudflare",
            bypass_used="double encoding",
        )

        assert finding.waf_detected == "Cloudflare"
        assert finding.bypass_used == "double encoding"

    def test_finding_model_dump(self):
        """Test XSSFinding serialization."""
        finding = XSSFinding(
            target_url="https://example.com/test",
            vulnerable=True,
            xss_type="dom",
            parameter="input",
        )

        data = finding.model_dump()
        assert "target_url" in data
        assert "vulnerable" in data
        assert "xss_type" in data
        assert data["xss_type"] == "dom"


class TestXSSType:
    """Test XSSType enum."""

    def test_xss_type_values(self):
        """Test XSS type enum values."""
        assert XSSType.REFLECTED.value == "reflected"
        assert XSSType.STORED.value == "stored"
        assert XSSType.DOM.value == "dom"
        assert XSSType.BLIND.value == "blind"


class TestXSStrikeAgentInit:
    """Test XSStrikeAgent initialization."""

    @patch("src.agents.assessment.xsstrike_agent.Sandbox")
    def test_creates_sandbox_if_not_provided(self, mock_sandbox_class, mock_backend):
        """Test that agent creates its own sandbox if not provided."""
        mock_sandbox_instance = Mock()
        mock_sandbox_class.create.return_value = mock_sandbox_instance

        agent = XSStrikeAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
        )

        mock_sandbox_class.create.assert_called_once()
        assert agent._owns_sandbox is True

    def test_uses_provided_sandbox(self, mock_backend, mock_sandbox):
        """Test that agent uses provided sandbox."""
        agent = XSStrikeAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        assert agent.sandbox == mock_sandbox
        assert agent._owns_sandbox is False


class TestXSStrikeAgentValidation:
    """Test URL validation."""

    def test_validate_url_valid_http(self, mock_backend, mock_sandbox):
        """Test valid HTTP URL passes validation."""
        agent = XSStrikeAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        # Should not raise
        agent._validate_url("http://example.com")
        agent._validate_url("https://example.com")
        agent._validate_url("https://example.com:8080")
        agent._validate_url("https://example.com/path?q=test")

    def test_validate_url_invalid(self, mock_backend, mock_sandbox):
        """Test invalid URLs fail validation."""
        agent = XSStrikeAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        with pytest.raises(ValueError):
            agent._validate_url("example.com")  # Missing scheme

        with pytest.raises(ValueError):
            agent._validate_url("ftp://example.com")  # Wrong scheme


class TestXSStrikeAgentParsing:
    """Test XSStrike output parsing."""

    def test_parse_vulnerable_output(self, mock_backend, mock_sandbox):
        """Test parsing output with XSS detected."""
        agent = XSStrikeAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        raw_output = """[+] Vulnerable: parameter=q
Payload: <script>alert(1)</script>
Context: attribute
Reflected XSS"""
        target_url = "https://example.com/search?q=test"

        findings = agent._parse_output(raw_output, target_url)

        assert len(findings) == 1
        assert findings[0].vulnerable is True
        assert findings[0].payload == "<script>alert(1)</script>"
        assert findings[0].context == "attribute"
        assert findings[0].xss_type == "reflected"

    def test_parse_not_vulnerable_output(self, mock_backend, mock_sandbox):
        """Test parsing output with no XSS detected."""
        agent = XSStrikeAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        raw_output = "No vulnerabilities found in the target"
        target_url = "https://example.com/search?q=test"

        findings = agent._parse_output(raw_output, target_url)

        assert len(findings) == 1
        assert findings[0].vulnerable is False

    def test_parse_dom_xss(self, mock_backend, mock_sandbox):
        """Test parsing DOM-based XSS."""
        agent = XSStrikeAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        raw_output = """[+] Vulnerable
DOM XSS detected
Payload: javascript:alert(1)"""
        target_url = "https://example.com/page#input=test"

        findings = agent._parse_output(raw_output, target_url)

        assert len(findings) == 1
        assert findings[0].xss_type == "dom"

    def test_parse_empty_output(self, mock_backend, mock_sandbox):
        """Test parsing empty output."""
        agent = XSStrikeAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        raw_output = ""
        target_url = "https://example.com/test"

        findings = agent._parse_output(raw_output, target_url)

        assert len(findings) == 1
        assert findings[0].vulnerable is False


class TestXSStrikeAgentExecution:
    """Test XSStrike execution."""

    def test_execute_success(self, mock_backend, mock_sandbox):
        """Test successful XSStrike execution."""
        # Setup mock sandbox responses
        mock_sandbox.commands.run.side_effect = [
            Mock(exit_code=0, stdout=""),  # XSStrike installed check
            Mock(exit_code=0, stdout="[+] Vulnerable\nPayload: <script>alert(1)</script>", stderr=""),
        ]

        agent = XSStrikeAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        findings = agent.execute("https://example.com/search?q=test")

        assert len(findings) >= 1
        mock_backend.write.assert_called()

    def test_execute_installs_xsstrike_if_missing(self, mock_backend, mock_sandbox):
        """Test that XSStrike is installed if not present."""
        mock_sandbox.commands.run.side_effect = [
            Mock(exit_code=1, stdout=""),  # XSStrike not found
            Mock(exit_code=0, stdout=""),  # git clone
            Mock(exit_code=0, stdout=""),  # pip install
            Mock(exit_code=0, stdout="No vulnerabilities", stderr=""),  # XSStrike execution
        ]

        agent = XSStrikeAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        findings = agent.execute("https://example.com/test")

        # Check that git clone was called
        calls = mock_sandbox.commands.run.call_args_list
        assert any("git clone" in str(call) for call in calls)


class TestXSStrikeAgentCleanup:
    """Test cleanup behavior."""

    def test_cleanup_kills_owned_sandbox(self, mock_backend):
        """Test cleanup kills sandbox when agent owns it."""
        with patch("src.agents.assessment.xsstrike_agent.Sandbox") as mock_sandbox_class:
            mock_sandbox_instance = Mock()
            mock_sandbox_class.create.return_value = mock_sandbox_instance

            agent = XSStrikeAgent(
                scan_id="test-scan",
                team_id="test-team",
                nexus_backend=mock_backend,
            )

            agent.cleanup()

            mock_sandbox_instance.kill.assert_called_once()

    def test_cleanup_does_not_kill_provided_sandbox(self, mock_backend, mock_sandbox):
        """Test cleanup doesn't kill sandbox when provided externally."""
        agent = XSStrikeAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        agent.cleanup()

        mock_sandbox.kill.assert_not_called()
