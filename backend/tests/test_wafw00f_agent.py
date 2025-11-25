"""
Unit tests for wafw00f Agent.

Tests use mocks to avoid E2B sandbox dependencies.
For E2E integration tests, see tests/integration/test_wafw00f_e2e.py
"""

import pytest
import json
from unittest.mock import Mock, MagicMock, patch

from src.agents.recon.wafw00f_agent import (
    Wafw00fAgent,
    WafFinding,
    Wafw00fError,
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


class TestWafFinding:
    """Test WafFinding data model."""

    def test_finding_creation_with_waf(self):
        """Test creating a WafFinding with WAF detected."""
        finding = WafFinding(
            target="https://example.com",
            waf_detected=True,
            waf_name="Cloudflare",
            waf_vendor="Cloudflare Inc.",
            confidence="high",
            detection_method="wafw00f fingerprinting",
        )

        assert finding.target == "https://example.com"
        assert finding.waf_detected is True
        assert finding.waf_name == "Cloudflare"
        assert finding.waf_vendor == "Cloudflare Inc."
        assert finding.confidence == "high"

    def test_finding_creation_no_waf(self):
        """Test creating a WafFinding with no WAF detected."""
        finding = WafFinding(
            target="https://example.com",
            waf_detected=False,
            confidence="high",
        )

        assert finding.target == "https://example.com"
        assert finding.waf_detected is False
        assert finding.waf_name is None
        assert finding.confidence == "high"

    def test_finding_model_dump(self):
        """Test WafFinding serialization."""
        finding = WafFinding(
            target="https://example.com",
            waf_detected=True,
            waf_name="AWS WAF",
            confidence="medium",
        )

        data = finding.model_dump()
        assert "target" in data
        assert "waf_detected" in data
        assert "waf_name" in data
        assert data["waf_name"] == "AWS WAF"


class TestWafw00fAgentInit:
    """Test Wafw00fAgent initialization."""

    @patch("src.agents.recon.wafw00f_agent.Sandbox")
    def test_creates_sandbox_if_not_provided(self, mock_sandbox_class, mock_backend):
        """Test that agent creates its own sandbox if not provided."""
        mock_sandbox_instance = Mock()
        mock_sandbox_class.create.return_value = mock_sandbox_instance

        agent = Wafw00fAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
        )

        mock_sandbox_class.create.assert_called_once()
        assert agent._owns_sandbox is True

    def test_uses_provided_sandbox(self, mock_backend, mock_sandbox):
        """Test that agent uses provided sandbox."""
        agent = Wafw00fAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        assert agent.sandbox == mock_sandbox
        assert agent._owns_sandbox is False


class TestWafw00fAgentValidation:
    """Test URL validation."""

    def test_validate_url_valid_http(self, mock_backend, mock_sandbox):
        """Test valid HTTP URL passes validation."""
        agent = Wafw00fAgent(
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
        agent = Wafw00fAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        with pytest.raises(ValueError):
            agent._validate_url("example.com")  # Missing scheme

        with pytest.raises(ValueError):
            agent._validate_url("ftp://example.com")  # Wrong scheme


class TestWafw00fAgentParsing:
    """Test wafw00f output parsing."""

    def test_parse_waf_detected(self, mock_backend, mock_sandbox):
        """Test parsing output with WAF detected."""
        agent = Wafw00fAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        raw_output = "https://example.com is behind Cloudflare (Cloudflare Inc.)"
        targets = ["https://example.com"]

        findings = agent._parse_output(raw_output, targets)

        assert len(findings) == 1
        assert findings[0].waf_detected is True
        assert findings[0].waf_name == "Cloudflare"
        assert findings[0].confidence == "high"

    def test_parse_no_waf_detected(self, mock_backend, mock_sandbox):
        """Test parsing output with no WAF detected."""
        agent = Wafw00fAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        raw_output = "https://example.com No WAF detected by the generic detection"
        targets = ["https://example.com"]

        findings = agent._parse_output(raw_output, targets)

        assert len(findings) == 1
        assert findings[0].waf_detected is False
        assert findings[0].confidence == "high"

    def test_parse_might_be_behind_waf(self, mock_backend, mock_sandbox):
        """Test parsing output with possible WAF."""
        agent = Wafw00fAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        raw_output = "https://example.com might be behind a WAF"
        targets = ["https://example.com"]

        findings = agent._parse_output(raw_output, targets)

        assert len(findings) == 1
        assert findings[0].waf_detected is True
        assert findings[0].confidence == "medium"

    def test_parse_multiple_targets(self, mock_backend, mock_sandbox):
        """Test parsing output with multiple targets."""
        agent = Wafw00fAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        raw_output = """https://example.com is behind Cloudflare (Cloudflare Inc.)
https://test.com No WAF detected by the generic detection"""
        targets = ["https://example.com", "https://test.com"]

        findings = agent._parse_output(raw_output, targets)

        assert len(findings) == 2
        assert findings[0].waf_detected is True
        assert findings[0].waf_name == "Cloudflare"
        assert findings[1].waf_detected is False

    def test_parse_known_waf_normalization(self, mock_backend, mock_sandbox):
        """Test that known WAF names are normalized."""
        agent = Wafw00fAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        # Test AWS WAF normalization
        raw_output = "https://example.com is behind aws waf"
        targets = ["https://example.com"]

        findings = agent._parse_output(raw_output, targets)

        assert len(findings) == 1
        assert findings[0].waf_name == "AWS WAF"


class TestWafw00fAgentExecution:
    """Test wafw00f execution."""

    def test_execute_success(self, mock_backend, mock_sandbox):
        """Test successful wafw00f execution."""
        # Setup mock sandbox responses
        mock_sandbox.commands.run.side_effect = [
            Mock(exit_code=0, stdout="/usr/bin/wafw00f"),  # which wafw00f
            Mock(exit_code=0, stdout=""),  # wafw00f execution
        ]

        mock_sandbox.files.write = Mock()
        mock_sandbox.files.read.return_value = "https://example.com is behind Cloudflare (Cloudflare Inc.)"

        agent = Wafw00fAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        findings = agent.execute(["https://example.com"])

        assert len(findings) == 1
        assert findings[0].waf_detected is True
        assert findings[0].waf_name == "Cloudflare"
        mock_backend.write.assert_called()

    def test_execute_installs_wafw00f_if_missing(self, mock_backend, mock_sandbox):
        """Test that wafw00f is installed if not present."""
        mock_sandbox.commands.run.side_effect = [
            Mock(exit_code=1, stdout=""),  # which wafw00f (not found)
            Mock(exit_code=0, stdout=""),  # pip install
            Mock(exit_code=0, stdout=""),  # wafw00f execution
        ]

        mock_sandbox.files.write = Mock()
        mock_sandbox.files.read.return_value = "https://example.com No WAF detected"

        agent = Wafw00fAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        findings = agent.execute(["https://example.com"])

        # Check that pip install was called
        calls = mock_sandbox.commands.run.call_args_list
        assert any("pip install wafw00f" in str(call) for call in calls)


class TestWafw00fAgentCleanup:
    """Test cleanup behavior."""

    def test_cleanup_kills_owned_sandbox(self, mock_backend):
        """Test cleanup kills sandbox when agent owns it."""
        with patch("src.agents.recon.wafw00f_agent.Sandbox") as mock_sandbox_class:
            mock_sandbox_instance = Mock()
            mock_sandbox_class.create.return_value = mock_sandbox_instance

            agent = Wafw00fAgent(
                scan_id="test-scan",
                team_id="test-team",
                nexus_backend=mock_backend,
            )

            agent.cleanup()

            mock_sandbox_instance.kill.assert_called_once()

    def test_cleanup_does_not_kill_provided_sandbox(self, mock_backend, mock_sandbox):
        """Test cleanup doesn't kill sandbox when provided externally."""
        agent = Wafw00fAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        agent.cleanup()

        mock_sandbox.kill.assert_not_called()


class TestKnownWAFs:
    """Test known WAF mappings."""

    def test_known_wafs_mapping(self):
        """Test that known WAFs are properly mapped."""
        assert Wafw00fAgent.KNOWN_WAFS["cloudflare"] == "Cloudflare"
        assert Wafw00fAgent.KNOWN_WAFS["aws"] == "AWS WAF"
        assert Wafw00fAgent.KNOWN_WAFS["akamai"] == "Akamai"
        assert Wafw00fAgent.KNOWN_WAFS["imperva"] == "Imperva"
        assert Wafw00fAgent.KNOWN_WAFS["modsecurity"] == "ModSecurity"
