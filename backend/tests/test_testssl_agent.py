"""
Unit tests for testssl.sh Agent.

Tests use mocks to avoid E2B sandbox dependencies.
For E2E integration tests, see tests/integration/test_testssl_e2e.py
"""

import pytest
import json
from unittest.mock import Mock, MagicMock, patch

from src.agents.assessment.testssl_agent import (
    TestsslAgent,
    TLSFinding,
    TLSVulnerability,
    CertificateInfo,
    TestsslError,
    TLSSeverity,
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


class TestTLSVulnerability:
    """Test TLSVulnerability data model."""

    def test_vulnerability_creation(self):
        """Test creating a TLSVulnerability."""
        vuln = TLSVulnerability(
            id="heartbleed",
            name="Heartbleed",
            severity="critical",
            finding="Server is vulnerable to Heartbleed",
            cve="CVE-2014-0160",
        )

        assert vuln.id == "heartbleed"
        assert vuln.name == "Heartbleed"
        assert vuln.severity == "critical"
        assert vuln.cve == "CVE-2014-0160"

    def test_vulnerability_model_dump(self):
        """Test TLSVulnerability serialization."""
        vuln = TLSVulnerability(
            id="poodle",
            name="POODLE",
            severity="high",
            finding="SSLv3 POODLE vulnerable",
        )

        data = vuln.model_dump()
        assert "id" in data
        assert "severity" in data
        assert data["severity"] == "high"


class TestCertificateInfo:
    """Test CertificateInfo data model."""

    def test_certificate_creation(self):
        """Test creating a CertificateInfo."""
        cert = CertificateInfo(
            subject="example.com",
            issuer="Let's Encrypt Authority X3",
            valid_from="2024-01-01",
            valid_until="2024-04-01",
            key_size=2048,
            is_expired=False,
        )

        assert cert.subject == "example.com"
        assert cert.issuer == "Let's Encrypt Authority X3"
        assert cert.key_size == 2048
        assert cert.is_expired is False

    def test_certificate_with_san(self):
        """Test CertificateInfo with Subject Alternative Names."""
        cert = CertificateInfo(
            subject="example.com",
            san=["www.example.com", "api.example.com"],
        )

        assert len(cert.san) == 2
        assert "www.example.com" in cert.san


class TestTLSFinding:
    """Test TLSFinding data model."""

    def test_finding_creation(self):
        """Test creating a TLSFinding."""
        finding = TLSFinding(
            target="example.com:443",
            port=443,
            protocols={"TLSv1.2": True, "TLSv1.3": True},
            overall_rating="A",
        )

        assert finding.target == "example.com:443"
        assert finding.port == 443
        assert finding.protocols["TLSv1.2"] is True
        assert finding.overall_rating == "A"

    def test_finding_with_vulnerabilities(self):
        """Test TLSFinding with vulnerabilities."""
        finding = TLSFinding(
            target="example.com:443",
            vulnerabilities=[
                TLSVulnerability(
                    id="heartbleed",
                    name="Heartbleed",
                    severity="critical",
                    finding="Vulnerable",
                )
            ],
            overall_rating="F",
        )

        assert len(finding.vulnerabilities) == 1
        assert finding.vulnerabilities[0].id == "heartbleed"


class TestTLSSeverity:
    """Test TLSSeverity enum."""

    def test_severity_values(self):
        """Test TLS severity enum values."""
        assert TLSSeverity.CRITICAL.value == "critical"
        assert TLSSeverity.HIGH.value == "high"
        assert TLSSeverity.MEDIUM.value == "medium"
        assert TLSSeverity.LOW.value == "low"
        assert TLSSeverity.INFO.value == "info"
        assert TLSSeverity.OK.value == "ok"


class TestTestsslAgentInit:
    """Test TestsslAgent initialization."""

    @patch("src.agents.assessment.testssl_agent.Sandbox")
    def test_creates_sandbox_if_not_provided(self, mock_sandbox_class, mock_backend):
        """Test that agent creates its own sandbox if not provided."""
        mock_sandbox_instance = Mock()
        mock_sandbox_class.create.return_value = mock_sandbox_instance

        agent = TestsslAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
        )

        mock_sandbox_class.create.assert_called_once()
        assert agent._owns_sandbox is True

    def test_uses_provided_sandbox(self, mock_backend, mock_sandbox):
        """Test that agent uses provided sandbox."""
        agent = TestsslAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        assert agent.sandbox == mock_sandbox
        assert agent._owns_sandbox is False


class TestTestsslAgentTargetNormalization:
    """Test target normalization."""

    def test_normalize_https_url(self, mock_backend, mock_sandbox):
        """Test normalizing https URL."""
        agent = TestsslAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        assert agent._normalize_target("https://example.com") == "example.com"
        assert agent._normalize_target("http://example.com") == "example.com"
        assert agent._normalize_target("https://example.com/path") == "example.com"
        assert agent._normalize_target("https://example.com:8443") == "example.com"

    def test_normalize_plain_hostname(self, mock_backend, mock_sandbox):
        """Test normalizing plain hostname."""
        agent = TestsslAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        assert agent._normalize_target("example.com") == "example.com"


class TestTestsslAgentParsing:
    """Test testssl output parsing."""

    def test_parse_json_output(self, mock_backend, mock_sandbox):
        """Test parsing JSON output."""
        agent = TestsslAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        json_output = json.dumps([
            {"id": "TLSv1.2", "severity": "OK", "finding": "offered"},
            {"id": "TLSv1.3", "severity": "OK", "finding": "offered"},
            {"id": "heartbleed", "severity": "OK", "finding": "not vulnerable"},
        ])

        finding = agent._parse_output(json_output, "example.com", 443)

        assert finding.target == "example.com:443"
        assert finding.protocols.get("TLSv1.2") is True
        assert finding.protocols.get("TLSv1.3") is True

    def test_parse_vulnerability_detected(self, mock_backend, mock_sandbox):
        """Test parsing output with vulnerability detected."""
        agent = TestsslAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        json_output = json.dumps([
            {"id": "heartbleed", "severity": "CRITICAL", "finding": "VULNERABLE"},
        ])

        finding = agent._parse_output(json_output, "example.com", 443)

        assert len(finding.vulnerabilities) == 1
        assert finding.vulnerabilities[0].id == "heartbleed"
        assert finding.vulnerabilities[0].severity == "critical"

    def test_parse_text_fallback(self, mock_backend, mock_sandbox):
        """Test parsing text output when JSON fails."""
        agent = TestsslAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        text_output = """
Testing protocols...
SSLv3 not offered
TLSv1.0 offered
TLSv1.2 offered
TLSv1.3 offered

Testing vulnerabilities...
Heartbleed: not vulnerable
"""

        finding = agent._parse_output(text_output, "example.com", 443)

        assert finding.target == "example.com:443"
        assert finding.protocols.get("TLSv1.0") is True


class TestTestsslAgentRating:
    """Test TLS rating calculation."""

    def test_rating_f_for_critical_vuln(self, mock_backend, mock_sandbox):
        """Test F rating for critical vulnerability."""
        agent = TestsslAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        finding = TLSFinding(
            target="example.com:443",
            vulnerabilities=[
                TLSVulnerability(
                    id="heartbleed",
                    name="Heartbleed",
                    severity="critical",
                    finding="VULNERABLE",
                )
            ],
        )

        agent._calculate_rating(finding)
        assert finding.overall_rating == "F"

    def test_rating_a_for_tls13(self, mock_backend, mock_sandbox):
        """Test A rating for TLS 1.3 with no issues."""
        agent = TestsslAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        finding = TLSFinding(
            target="example.com:443",
            protocols={"TLSv1.2": True, "TLSv1.3": True},
            vulnerabilities=[],
        )

        agent._calculate_rating(finding)
        assert finding.overall_rating == "A"


class TestTestsslAgentExecution:
    """Test testssl execution."""

    def test_execute_success(self, mock_backend, mock_sandbox):
        """Test successful testssl execution."""
        # Setup mock sandbox responses
        mock_sandbox.commands.run.side_effect = [
            Mock(exit_code=0, stdout=""),  # testssl installed check
            Mock(exit_code=0, stdout="", stderr=""),  # testssl execution
        ]

        json_output = json.dumps([
            {"id": "TLSv1.2", "severity": "OK", "finding": "offered"},
            {"id": "TLSv1.3", "severity": "OK", "finding": "offered"},
        ])
        mock_sandbox.files.read.return_value = json_output

        agent = TestsslAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        finding = agent.execute("example.com")

        assert finding.target == "example.com:443"
        mock_backend.write.assert_called()


class TestTestsslAgentCleanup:
    """Test cleanup behavior."""

    def test_cleanup_kills_owned_sandbox(self, mock_backend):
        """Test cleanup kills sandbox when agent owns it."""
        with patch("src.agents.assessment.testssl_agent.Sandbox") as mock_sandbox_class:
            mock_sandbox_instance = Mock()
            mock_sandbox_class.create.return_value = mock_sandbox_instance

            agent = TestsslAgent(
                scan_id="test-scan",
                team_id="test-team",
                nexus_backend=mock_backend,
            )

            agent.cleanup()

            mock_sandbox_instance.kill.assert_called_once()

    def test_cleanup_does_not_kill_provided_sandbox(self, mock_backend, mock_sandbox):
        """Test cleanup doesn't kill sandbox when provided externally."""
        agent = TestsslAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox,
        )

        agent.cleanup()

        mock_sandbox.kill.assert_not_called()


class TestKnownVulnerabilities:
    """Test known vulnerability checks."""

    def test_vuln_checks_list(self):
        """Test that vulnerability checks list is populated."""
        assert "heartbleed" in TestsslAgent.VULN_CHECKS
        assert "poodle_ssl" in TestsslAgent.VULN_CHECKS
        assert "robot" in TestsslAgent.VULN_CHECKS
        assert "drown" in TestsslAgent.VULN_CHECKS
        assert "freak" in TestsslAgent.VULN_CHECKS
        assert len(TestsslAgent.VULN_CHECKS) >= 10
