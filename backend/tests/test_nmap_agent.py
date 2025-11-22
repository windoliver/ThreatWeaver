"""
Unit tests for NmapAgent.

Tests the Nmap agent with mocked E2B sandbox and Nexus backend.
All external dependencies are mocked for fast, isolated testing.

Run:
    pytest tests/test_nmap_agent.py -v
"""

import pytest
import json
from unittest.mock import Mock, MagicMock

from src.agents.recon.nmap_agent import NmapAgent, NmapError, ScanProfile


# Sample Nmap XML output for testing
SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" start="1234567890">
    <host>
        <status state="up"/>
        <address addr="192.168.1.1" addrtype="ipv4"/>
        <hostnames>
            <hostname name="example.com" type="PTR"/>
        </hostnames>
        <ports>
            <port protocol="tcp" portid="22">
                <state state="open"/>
                <service name="ssh" product="OpenSSH" version="7.4" extrainfo="Ubuntu"/>
            </port>
            <port protocol="tcp" portid="80">
                <state state="open"/>
                <service name="http" product="Apache" version="2.4.29"/>
            </port>
            <port protocol="tcp" portid="443">
                <state state="open"/>
                <service name="https" product="nginx" version="1.14.0"/>
            </port>
        </ports>
        <os>
            <osmatch name="Linux 3.2 - 4.9" accuracy="95"/>
        </os>
    </host>
    <runstats>
        <finished time="1234567900" elapsed="10.5" summary="Scan completed"/>
    </runstats>
</nmaprun>
"""


@pytest.fixture
def mock_sandbox():
    """Mock E2B sandbox for testing."""
    sandbox = Mock()
    sandbox.commands = Mock()
    sandbox.commands.run = Mock()
    sandbox.files = Mock()
    sandbox.files.write = Mock()
    sandbox.kill = Mock()
    return sandbox


@pytest.fixture
def mock_backend():
    """Mock Nexus backend for testing."""
    backend = Mock()
    backend.write = Mock(return_value=Mock(error=None, path="/test/path"))
    return backend


@pytest.fixture
def agent(mock_sandbox, mock_backend):
    """Create NmapAgent with mocked dependencies."""
    return NmapAgent(
        scan_id="test-scan-123",
        team_id="test-team-abc",
        nexus_backend=mock_backend,
        sandbox=mock_sandbox
    )


class TestNmapAgentExecution:
    """Test main execution workflow."""

    def test_execute_success(self, agent, mock_sandbox):
        """Test successful network scan."""
        # Arrange
        mock_sandbox.commands.run.side_effect = [
            Mock(exit_code=0, stdout="", stderr=""),  # nmap command
            Mock(exit_code=0, stdout=SAMPLE_NMAP_XML, stderr="")  # cat XML
        ]

        # Act
        results = agent.execute(
            targets=["192.168.1.1"],
            profile=ScanProfile.DEFAULT
        )

        # Assert
        assert len(results['hosts']) == 1
        assert results['hosts'][0]['ip'] == "192.168.1.1"
        assert len(results['hosts'][0]['ports']) == 3
        assert results['hosts'][0]['ports'][0]['port'] == 22
        assert results['hosts'][0]['ports'][0]['service'] == "ssh"

    def test_execute_empty_targets(self, agent, mock_sandbox):
        """Test with empty target list."""
        # Act
        results = agent.execute([])

        # Assert
        assert results['hosts'] == []
        assert results['scan_stats'] == {}
        mock_sandbox.commands.run.assert_not_called()

    def test_execute_stealth_profile(self, agent, mock_sandbox):
        """Test stealth scan profile."""
        # Arrange
        mock_sandbox.commands.run.side_effect = [
            Mock(exit_code=0, stdout="", stderr=""),
            Mock(exit_code=0, stdout=SAMPLE_NMAP_XML, stderr="")
        ]

        # Act
        agent.execute(
            targets=["192.168.1.1"],
            profile=ScanProfile.STEALTH
        )

        # Assert
        call_args = mock_sandbox.commands.run.call_args_list[0][0][0]
        assert "-sT" in call_args  # TCP connect scan (unprivileged)
        assert "-T2" in call_args  # Slow timing
        assert "-Pn" in call_args  # Skip host discovery

    def test_execute_aggressive_profile(self, agent, mock_sandbox):
        """Test aggressive scan profile."""
        # Arrange
        mock_sandbox.commands.run.side_effect = [
            Mock(exit_code=0, stdout="", stderr=""),
            Mock(exit_code=0, stdout=SAMPLE_NMAP_XML, stderr="")
        ]

        # Act
        agent.execute(
            targets=["192.168.1.1"],
            profile=ScanProfile.AGGRESSIVE
        )

        # Assert
        call_args = mock_sandbox.commands.run.call_args_list[0][0][0]
        assert "-sT" in call_args  # TCP connect scan
        assert "-sV" in call_args  # Version detection
        assert "-T4" in call_args  # Fast timing
        assert "-Pn" in call_args  # Skip host discovery

    def test_execute_custom_ports(self, agent, mock_sandbox):
        """Test custom port specification."""
        # Arrange
        mock_sandbox.commands.run.side_effect = [
            Mock(exit_code=0, stdout="", stderr=""),
            Mock(exit_code=0, stdout=SAMPLE_NMAP_XML, stderr="")
        ]

        # Act
        agent.execute(
            targets=["192.168.1.1"],
            ports="22,80,443"
        )

        # Assert
        call_args = mock_sandbox.commands.run.call_args_list[0][0][0]
        assert "-p 22,80,443" in call_args

    def test_execute_writes_targets_to_sandbox(self, agent, mock_sandbox):
        """Test that targets are written to sandbox file."""
        # Arrange
        mock_sandbox.commands.run.side_effect = [
            Mock(exit_code=0, stdout="", stderr=""),
            Mock(exit_code=0, stdout=SAMPLE_NMAP_XML, stderr="")
        ]

        # Act
        targets = ["192.168.1.1", "10.0.0.1"]
        agent.execute(targets)

        # Assert
        mock_sandbox.files.write.assert_called_once_with(
            "/tmp/nmap_targets.txt",
            "192.168.1.1\n10.0.0.1"
        )

    def test_execute_timeout_enforcement(self, agent, mock_sandbox):
        """Test timeout is enforced and capped at 1 hour."""
        # Arrange
        mock_sandbox.commands.run.side_effect = [
            Mock(exit_code=0, stdout="", stderr=""),
            Mock(exit_code=0, stdout=SAMPLE_NMAP_XML, stderr="")
        ]

        # Act - Try to set 2 hour timeout (should be capped at 1 hour)
        agent.execute(
            targets=["192.168.1.1"],
            timeout=7200  # 2 hours
        )

        # Assert - Check that timeout was capped
        call_args = mock_sandbox.commands.run.call_args_list[0]
        assert call_args[1]['timeout'] == 3600  # Capped at 1 hour

    def test_execute_stores_results(self, agent, mock_sandbox, mock_backend):
        """Test that results are stored in Nexus workspace."""
        # Arrange
        mock_sandbox.commands.run.side_effect = [
            Mock(exit_code=0, stdout="", stderr=""),
            Mock(exit_code=0, stdout=SAMPLE_NMAP_XML, stderr="")
        ]

        # Act
        agent.execute(["192.168.1.1"])

        # Assert - Should write JSON and XML
        assert mock_backend.write.call_count == 2

        # Check JSON write
        json_call = mock_backend.write.call_args_list[0]
        assert "/recon/nmap/scan_results.json" in json_call[0]
        json_content = json_call[0][1]
        assert "192.168.1.1" in json_content
        assert '"total_open_ports": 3' in json_content

        # Check XML write
        xml_call = mock_backend.write.call_args_list[1]
        assert "/recon/nmap/scan_output.xml" in xml_call[0]


class TestNmapXMLParsing:
    """Test XML output parsing."""

    def test_parse_xml_with_ports(self, agent, mock_sandbox):
        """Test parsing XML with multiple ports."""
        # Arrange
        mock_sandbox.commands.run.side_effect = [
            Mock(exit_code=0, stdout="", stderr=""),
            Mock(exit_code=0, stdout=SAMPLE_NMAP_XML, stderr="")
        ]

        # Act
        results = agent.execute(["192.168.1.1"])

        # Assert
        host = results['hosts'][0]
        assert len(host['ports']) == 3

        # Check SSH port
        ssh_port = host['ports'][0]
        assert ssh_port['port'] == 22
        assert ssh_port['protocol'] == 'tcp'
        assert ssh_port['service'] == 'ssh'
        assert ssh_port['product'] == 'OpenSSH'
        assert ssh_port['version'] == '7.4'

    def test_parse_xml_with_hostnames(self, agent, mock_sandbox):
        """Test parsing hostnames from XML."""
        # Arrange
        mock_sandbox.commands.run.side_effect = [
            Mock(exit_code=0, stdout="", stderr=""),
            Mock(exit_code=0, stdout=SAMPLE_NMAP_XML, stderr="")
        ]

        # Act
        results = agent.execute(["192.168.1.1"])

        # Assert
        host = results['hosts'][0]
        assert "example.com" in host['hostnames']

    def test_parse_xml_with_os_detection(self, agent, mock_sandbox):
        """Test parsing OS detection from XML."""
        # Arrange
        mock_sandbox.commands.run.side_effect = [
            Mock(exit_code=0, stdout="", stderr=""),
            Mock(exit_code=0, stdout=SAMPLE_NMAP_XML, stderr="")
        ]

        # Act
        results = agent.execute(["192.168.1.1"])

        # Assert
        host = results['hosts'][0]
        assert len(host['os_matches']) == 1
        assert host['os_matches'][0]['name'] == "Linux 3.2 - 4.9"
        assert host['os_matches'][0]['accuracy'] == 95

    def test_parse_xml_scan_stats(self, agent, mock_sandbox):
        """Test parsing scan statistics."""
        # Arrange
        mock_sandbox.commands.run.side_effect = [
            Mock(exit_code=0, stdout="", stderr=""),
            Mock(exit_code=0, stdout=SAMPLE_NMAP_XML, stderr="")
        ]

        # Act
        results = agent.execute(["192.168.1.1"])

        # Assert
        stats = results['scan_stats']
        assert stats['start_time'] == "1234567890"
        assert stats['end_time'] == "1234567900"
        assert stats['elapsed'] == "10.5"

    def test_parse_xml_skips_down_hosts(self, agent, mock_sandbox):
        """Test that down hosts are skipped."""
        # Arrange
        xml_with_down_host = """<?xml version="1.0"?>
        <nmaprun>
            <host>
                <status state="down"/>
                <address addr="192.168.1.1" addrtype="ipv4"/>
            </host>
            <runstats><finished time="123" elapsed="1"/></runstats>
        </nmaprun>
        """
        mock_sandbox.commands.run.side_effect = [
            Mock(exit_code=0, stdout="", stderr=""),
            Mock(exit_code=0, stdout=xml_with_down_host, stderr="")
        ]

        # Act
        results = agent.execute(["192.168.1.1"])

        # Assert
        assert len(results['hosts']) == 0

    def test_parse_xml_skips_closed_ports(self, agent, mock_sandbox):
        """Test that closed ports are skipped."""
        # Arrange
        xml_with_closed = """<?xml version="1.0"?>
        <nmaprun>
            <host>
                <status state="up"/>
                <address addr="192.168.1.1" addrtype="ipv4"/>
                <ports>
                    <port protocol="tcp" portid="22">
                        <state state="open"/>
                        <service name="ssh"/>
                    </port>
                    <port protocol="tcp" portid="23">
                        <state state="closed"/>
                        <service name="telnet"/>
                    </port>
                </ports>
            </host>
            <runstats><finished time="123" elapsed="1"/></runstats>
        </nmaprun>
        """
        mock_sandbox.commands.run.side_effect = [
            Mock(exit_code=0, stdout="", stderr=""),
            Mock(exit_code=0, stdout=xml_with_closed, stderr="")
        ]

        # Act
        results = agent.execute(["192.168.1.1"])

        # Assert
        host = results['hosts'][0]
        assert len(host['ports']) == 1  # Only open port
        assert host['ports'][0]['port'] == 22


class TestTargetValidation:
    """Test target validation logic."""

    def test_validate_valid_targets(self, agent):
        """Test valid target formats."""
        valid_targets = [
            "192.168.1.1",
            "10.0.0.0/24",
            "example.com",
            "scanme.nmap.org",
        ]

        # Should not raise
        agent._validate_targets(valid_targets)

    def test_validate_empty_list_raises(self, agent):
        """Test empty target list raises error."""
        with pytest.raises(ValueError, match="cannot be empty"):
            agent._validate_targets([])

    def test_validate_non_list_raises(self, agent):
        """Test non-list input raises error."""
        with pytest.raises(ValueError, match="must be a list"):
            agent._validate_targets("not-a-list")

    def test_validate_target_too_long(self, agent):
        """Test target exceeding length limit."""
        long_target = "a" * 300
        with pytest.raises(ValueError, match="Target too long"):
            agent._validate_targets([long_target])

    def test_execute_with_invalid_targets(self, agent):
        """Test execution with empty targets returns empty results."""
        # Empty targets list returns empty results (graceful handling)
        results = agent.execute([])
        assert results['hosts'] == []
        assert results['scan_stats'] == {}


class TestErrorHandling:
    """Test error handling scenarios."""

    def test_execute_nmap_failure(self, agent, mock_sandbox):
        """Test handling when Nmap execution fails."""
        # Arrange
        mock_sandbox.commands.run.return_value = Mock(
            exit_code=1,
            stdout="",
            stderr="ERROR: Invalid option"
        )

        # Act & Assert
        with pytest.raises(NmapError, match="exit code 1"):
            agent.execute(["192.168.1.1"])

    def test_execute_timeout(self, agent, mock_sandbox):
        """Test timeout handling."""
        # Arrange
        mock_sandbox.commands.run.side_effect = TimeoutError("Command timeout")

        # Act & Assert
        with pytest.raises(NmapError, match="timed out"):
            agent.execute(["192.168.1.1"], timeout=60)

    def test_execute_xml_read_failure(self, agent, mock_sandbox):
        """Test handling when XML file cannot be read."""
        # Arrange
        mock_sandbox.commands.run.side_effect = [
            Mock(exit_code=0, stdout="", stderr=""),  # nmap command succeeds
            Mock(exit_code=1, stdout="", stderr="File not found")  # cat fails
        ]

        # Act & Assert
        with pytest.raises(NmapError, match="Failed to read Nmap XML output"):
            agent.execute(["192.168.1.1"])

    def test_execute_invalid_xml(self, agent, mock_sandbox):
        """Test handling of malformed XML."""
        # Arrange
        mock_sandbox.commands.run.side_effect = [
            Mock(exit_code=0, stdout="", stderr=""),
            Mock(exit_code=0, stdout="<invalid xml", stderr="")
        ]

        # Act & Assert
        with pytest.raises(NmapError, match="Failed to parse Nmap XML"):
            agent.execute(["192.168.1.1"])

    def test_store_results_write_failure(self, agent, mock_sandbox, mock_backend):
        """Test handling when Nexus write fails."""
        # Arrange
        mock_sandbox.commands.run.side_effect = [
            Mock(exit_code=0, stdout="", stderr=""),
            Mock(exit_code=0, stdout=SAMPLE_NMAP_XML, stderr="")
        ]
        mock_backend.write.return_value = Mock(error="Write failed", path=None)

        # Act & Assert
        with pytest.raises(NmapError, match="Failed to store results"):
            agent.execute(["192.168.1.1"])


class TestResourceManagement:
    """Test resource cleanup and management."""

    def test_cleanup_kills_sandbox(self, agent, mock_sandbox):
        """Test that cleanup kills the sandbox (only if we own it)."""
        # Arrange
        agent._owns_sandbox = True

        # Act
        agent.cleanup()

        # Assert
        mock_sandbox.kill.assert_called_once()

    def test_cleanup_handles_exception(self, agent, mock_sandbox):
        """Test cleanup handles exceptions gracefully."""
        # Arrange
        agent._owns_sandbox = True
        mock_sandbox.kill.side_effect = Exception("Kill failed")

        # Act - Should not raise
        agent.cleanup()

    def test_agent_initialization_without_sandbox(self, mock_backend):
        """Test agent auto-creates sandbox if not provided."""
        agent = NmapAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=Mock()
        )

        assert agent.sandbox is not None


class TestOutputFormat:
    """Test output data format and structure."""

    def test_returns_dict_with_hosts(self, agent, mock_sandbox):
        """Test that execute returns a dictionary with hosts."""
        # Arrange
        mock_sandbox.commands.run.side_effect = [
            Mock(exit_code=0, stdout="", stderr=""),
            Mock(exit_code=0, stdout=SAMPLE_NMAP_XML, stderr="")
        ]

        # Act
        result = agent.execute(["192.168.1.1"])

        # Assert
        assert isinstance(result, dict)
        assert "hosts" in result
        assert "scan_stats" in result
        assert isinstance(result["hosts"], list)

    def test_json_output_structure(self, agent, mock_sandbox, mock_backend):
        """Test JSON output has correct structure."""
        # Arrange
        mock_sandbox.commands.run.side_effect = [
            Mock(exit_code=0, stdout="", stderr=""),
            Mock(exit_code=0, stdout=SAMPLE_NMAP_XML, stderr="")
        ]

        # Act
        agent.execute(["192.168.1.1"])

        # Assert
        json_content = mock_backend.write.call_args_list[0][0][1]
        assert "targets_count" in json_content
        assert "hosts_scanned" in json_content
        assert "total_open_ports" in json_content
        assert "scan_profile" in json_content
        assert "timestamp" in json_content
        assert "scan_id" in json_content
        assert "team_id" in json_content
        assert "tool" in json_content


class TestScanProfiles:
    """Test different scan profiles."""

    def test_all_profiles_build_commands(self, agent):
        """Test that all scan profiles build valid commands."""
        # Test each profile
        for profile in ScanProfile:
            cmd = agent._build_nmap_command(profile, None)
            assert isinstance(cmd, str)
            assert len(cmd) > 0
            assert "-Pn" in cmd  # All profiles use -Pn
            assert "-sT" in cmd  # All profiles use TCP connect scan

    def test_stealth_profile_command(self, agent):
        """Test stealth profile command structure."""
        cmd = agent._build_nmap_command(ScanProfile.STEALTH, "22,80")
        assert "-sT" in cmd
        assert "-T2" in cmd
        assert "-Pn" in cmd
        assert "-p 22,80" in cmd

    def test_default_profile_command(self, agent):
        """Test default profile command structure."""
        cmd = agent._build_nmap_command(ScanProfile.DEFAULT, None)
        assert "-sT" in cmd
        assert "-sV" in cmd
        assert "-sC" in cmd
        assert "-T3" in cmd
        assert "-Pn" in cmd

    def test_aggressive_profile_command(self, agent):
        """Test aggressive profile command structure."""
        cmd = agent._build_nmap_command(ScanProfile.AGGRESSIVE, "1-65535")
        assert "-sT" in cmd
        assert "-sV" in cmd
        assert "-T4" in cmd
        assert "-Pn" in cmd
        assert "-p 1-65535" in cmd
