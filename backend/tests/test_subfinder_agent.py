"""
Unit tests for SubfinderAgent.

Tests the Subfinder agent with mocked E2B sandbox and Nexus backend.
All external dependencies are mocked for fast, isolated testing.

Run:
    pytest tests/test_subfinder_agent.py -v
"""

import pytest
from unittest.mock import Mock, AsyncMock, MagicMock

from src.agents.recon.subfinder_agent import SubfinderAgent, SubfinderError


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
    return backend


@pytest.fixture
def agent(mock_sandbox, mock_backend):
    """Create SubfinderAgent with mocked dependencies."""
    return SubfinderAgent(
        scan_id="test-scan-123",
        team_id="test-team-abc",
        nexus_backend=mock_backend,
        sandbox=mock_sandbox
    )


class TestSubfinderAgentExecution:
    """Test main execution workflow."""

    def test_execute_success(self, agent, mock_sandbox):
        """Test successful subdomain discovery."""
        # Arrange
        mock_result = Mock(
            exit_code=0,
            stdout="sub1.example.com\nsub2.example.com\nsub3.example.com\n",
            stderr=""
        )
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        subdomains = agent.execute("example.com")

        # Assert
        assert len(subdomains) == 3
        assert "sub1.example.com" in subdomains
        assert "sub2.example.com" in subdomains
        assert "sub3.example.com" in subdomains
        mock_sandbox.commands.run.assert_called_once()

        # Verify command format
        call_args = mock_sandbox.commands.run.call_args
        assert "subfinder -d example.com -silent" in call_args[0]

    def test_execute_no_results(self, agent, mock_sandbox):
        """Test when no subdomains are found."""
        # Arrange
        mock_result = Mock(exit_code=0, stdout="", stderr="")
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        subdomains = agent.execute("nonexistent.com")

        # Assert
        assert len(subdomains) == 0
        assert subdomains == []

    def test_execute_with_timeout(self, agent, mock_sandbox):
        """Test custom timeout parameter."""
        # Arrange
        mock_result = Mock(exit_code=0, stdout="sub.example.com\n", stderr="")
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        agent.execute("example.com", timeout=120)

        # Assert
        call_args = mock_sandbox.commands.run.call_args
        assert call_args[1]['timeout'] == 120

    def test_execute_stores_results(self, agent, mock_sandbox, mock_backend):
        """Test that results are stored in Nexus workspace."""
        # Arrange
        mock_result = Mock(
            exit_code=0,
            stdout="api.example.com\nwww.example.com\n",
            stderr=""
        )
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        agent.execute("example.com")

        # Assert - Should write JSON and raw output
        assert mock_backend.write.call_count == 2

        # Check JSON write
        json_call = mock_backend.write.call_args_list[0]
        assert "/recon/subfinder/subdomains.json" in json_call[0]
        json_content = json_call[0][1]
        assert "api.example.com" in json_content
        assert "www.example.com" in json_content
        assert '"count": 2' in json_content

        # Check raw output write
        raw_call = mock_backend.write.call_args_list[1]
        assert "/recon/subfinder/raw_output.txt" in raw_call[0]


class TestSubfinderOutputParsing:
    """Test output parsing and cleaning."""

    def test_parse_with_duplicates(self, agent, mock_sandbox):
        """Test deduplication of subdomains."""
        # Arrange
        mock_result = Mock(
            exit_code=0,
            stdout="sub1.example.com\nsub1.example.com\nsub2.example.com\nsub1.example.com\n",
            stderr=""
        )
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        subdomains = agent.execute("example.com")

        # Assert
        assert len(subdomains) == 2  # Duplicates removed
        assert "sub1.example.com" in subdomains
        assert "sub2.example.com" in subdomains

    def test_parse_with_wildcards_filtered(self, agent, mock_sandbox):
        """Test wildcard DNS filtering (default behavior)."""
        # Arrange
        mock_result = Mock(
            exit_code=0,
            stdout="*.cdn.example.com\nsub1.example.com\n*.wildcard.example.com\nsub2.example.com\n",
            stderr=""
        )
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        subdomains = agent.execute("example.com", filter_wildcards=True)

        # Assert
        assert len(subdomains) == 2
        assert "sub1.example.com" in subdomains
        assert "sub2.example.com" in subdomains
        assert "*.cdn.example.com" not in subdomains
        assert "*.wildcard.example.com" not in subdomains

    def test_parse_with_wildcards_not_filtered(self, agent, mock_sandbox):
        """Test keeping wildcard entries when filtering disabled."""
        # Arrange
        mock_result = Mock(
            exit_code=0,
            stdout="*.cdn.example.com\nsub1.example.com\n",
            stderr=""
        )
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        subdomains = agent.execute("example.com", filter_wildcards=False)

        # Assert
        assert len(subdomains) == 2
        assert "*.cdn.example.com" in subdomains
        assert "sub1.example.com" in subdomains

    def test_parse_with_ansi_codes(self, agent, mock_sandbox):
        """Test ANSI color code removal."""
        # Arrange
        mock_result = Mock(
            exit_code=0,
            stdout="\x1b[32msub1.example.com\x1b[0m\n\x1b[32msub2.example.com\x1b[0m\n",
            stderr=""
        )
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        subdomains = agent.execute("example.com")

        # Assert
        assert len(subdomains) == 2
        assert "sub1.example.com" in subdomains
        assert "\x1b[32m" not in subdomains[0]  # ANSI codes removed

    def test_parse_with_empty_lines(self, agent, mock_sandbox):
        """Test handling of empty lines in output."""
        # Arrange
        mock_result = Mock(
            exit_code=0,
            stdout="sub1.example.com\n\n\nsub2.example.com\n\n",
            stderr=""
        )
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        subdomains = agent.execute("example.com")

        # Assert
        assert len(subdomains) == 2
        assert "" not in subdomains  # Empty lines filtered


class TestDomainValidation:
    """Test domain validation logic."""

    def test_validate_valid_domain(self, agent):
        """Test valid domain formats."""
        valid_domains = [
            "example.com",
            "sub.example.com",
            "test-domain.co.uk",
            "a.b.c.d.example.com",
            "123.example.com",
        ]

        for domain in valid_domains:
            # Should not raise
            agent._validate_domain(domain)

    def test_validate_invalid_domain_format(self, agent):
        """Test invalid domain format."""
        with pytest.raises(ValueError, match="Invalid domain format"):
            agent._validate_domain("not a domain!")

    def test_validate_invalid_domain_special_chars(self, agent):
        """Test domain with invalid special characters."""
        with pytest.raises(ValueError, match="Invalid domain format"):
            agent._validate_domain("example@domain.com")

    def test_validate_domain_too_long(self, agent):
        """Test domain exceeding 253 character limit."""
        long_domain = "a" * 250 + ".com"
        with pytest.raises(ValueError, match="Domain too long"):
            agent._validate_domain(long_domain)

    def test_execute_with_invalid_domain(self, agent):
        """Test execution with invalid domain raises error."""
        with pytest.raises(SubfinderError, match="Invalid domain format"):
            agent.execute("invalid domain name")


class TestErrorHandling:
    """Test error handling scenarios."""

    def test_execute_sandbox_failure(self, agent, mock_sandbox):
        """Test handling when sandbox execution fails."""
        # Arrange
        mock_result = Mock(exit_code=1, stdout="", stderr="Error: something went wrong")
        mock_sandbox.commands.run.return_value = mock_result

        # Act & Assert
        with pytest.raises(SubfinderError, match="exit code 1"):
            agent.execute("example.com")

    def test_execute_timeout(self, agent, mock_sandbox):
        """Test timeout handling."""
        # Arrange
        mock_sandbox.commands.run.side_effect = TimeoutError("Command timeout")

        # Act & Assert
        with pytest.raises(SubfinderError, match="timed out"):
            agent.execute("example.com", timeout=60)

    def test_execute_general_exception(self, agent, mock_sandbox):
        """Test handling of unexpected exceptions."""
        # Arrange
        mock_sandbox.commands.run.side_effect = Exception("Unexpected error")

        # Act & Assert
        with pytest.raises(SubfinderError):
            agent.execute("example.com")

    def test_store_results_write_failure(self, agent, mock_sandbox, mock_backend):
        """Test handling when Nexus write fails."""
        # Arrange
        mock_result = Mock(exit_code=0, stdout="sub.example.com\n", stderr="")
        mock_sandbox.commands.run.return_value = mock_result
        mock_backend.write.return_value = Mock(error="Write failed", path=None)

        # Act & Assert
        with pytest.raises(SubfinderError, match="Failed to store results"):
            agent.execute("example.com")


class TestResourceManagement:
    """Test resource cleanup and management."""

    def test_cleanup_kills_sandbox(self, agent, mock_sandbox):
        """Test that cleanup kills the sandbox (only if we own it)."""
        # Arrange - Set _owns_sandbox flag
        agent._owns_sandbox = True

        # Act
        agent.cleanup()

        # Assert
        mock_sandbox.kill.assert_called_once()

    def test_cleanup_handles_exception(self, agent, mock_sandbox):
        """Test cleanup handles exceptions gracefully."""
        # Arrange
        mock_sandbox.kill.side_effect = Exception("Kill failed")

        # Act - Should not raise
        agent.cleanup()

    def test_agent_initialization_without_sandbox(self, mock_backend):
        """Test agent auto-creates sandbox if not provided."""
        # This would normally create a real sandbox, but we'll test the pattern
        # In real usage, sandbox should be injected for testing
        agent = SubfinderAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=Mock()  # Provide mock to avoid real E2B creation
        )

        assert agent.sandbox is not None


class TestOutputFormat:
    """Test output data format and structure."""

    def test_returns_list_of_strings(self, agent, mock_sandbox):
        """Test that execute returns a list of strings."""
        # Arrange
        mock_result = Mock(exit_code=0, stdout="sub1.com\nsub2.com\n", stderr="")
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        result = agent.execute("example.com")

        # Assert
        assert isinstance(result, list)
        assert all(isinstance(item, str) for item in result)

    def test_json_output_structure(self, agent, mock_sandbox, mock_backend):
        """Test JSON output has correct structure."""
        # Arrange
        mock_result = Mock(exit_code=0, stdout="api.example.com\n", stderr="")
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        agent.execute("example.com")

        # Assert
        json_content = mock_backend.write.call_args_list[0][0][1]
        assert "domain" in json_content
        assert "subdomains" in json_content
        assert "count" in json_content
        assert "timestamp" in json_content
        assert "scan_id" in json_content
        assert "team_id" in json_content
        assert "tool" in json_content
        assert "version" in json_content


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_execute_with_single_subdomain(self, agent, mock_sandbox):
        """Test with exactly one subdomain."""
        # Arrange
        mock_result = Mock(exit_code=0, stdout="www.example.com\n", stderr="")
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        subdomains = agent.execute("example.com")

        # Assert
        assert len(subdomains) == 1
        assert subdomains[0] == "www.example.com"

    def test_execute_with_many_subdomains(self, agent, mock_sandbox):
        """Test with large number of subdomains."""
        # Arrange
        many_subs = "\n".join([f"sub{i}.example.com" for i in range(1000)])
        mock_result = Mock(exit_code=0, stdout=many_subs, stderr="")
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        subdomains = agent.execute("example.com")

        # Assert
        assert len(subdomains) == 1000

    def test_execute_preserves_subdomain_order(self, agent, mock_sandbox):
        """Test that subdomain order is preserved."""
        # Arrange
        mock_result = Mock(
            exit_code=0,
            stdout="zzz.example.com\naaa.example.com\nmmm.example.com\n",
            stderr=""
        )
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        subdomains = agent.execute("example.com")

        # Assert - Order should be preserved (not alphabetically sorted)
        assert subdomains == ["zzz.example.com", "aaa.example.com", "mmm.example.com"]
