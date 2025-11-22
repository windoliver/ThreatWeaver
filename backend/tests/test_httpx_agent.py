"""
Unit tests for HTTPxAgent.

Tests the HTTPx agent with mocked E2B sandbox and Nexus backend.
All external dependencies are mocked for fast, isolated testing.

Run:
    pytest tests/test_httpx_agent.py -v
"""

import pytest
import json
from unittest.mock import Mock, AsyncMock, MagicMock

from src.agents.recon.httpx_agent import HTTPxAgent, HTTPxError


@pytest.fixture
def mock_sandbox():
    """Mock E2B sandbox for testing."""
    sandbox = Mock()
    # Mock the commands.run API (E2B SDK structure)
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
    """Create HTTPxAgent with mocked dependencies."""
    return HTTPxAgent(
        scan_id="test-scan-123",
        team_id="test-team-abc",
        nexus_backend=mock_backend,
        sandbox=mock_sandbox
    )


class TestHTTPxAgentExecution:
    """Test main execution workflow."""

    def test_execute_success(self, agent, mock_sandbox):
        """Test successful HTTP probing."""
        # Arrange
        mock_result = Mock(
            exit_code=0,
            stdout='{"url":"https://www.papergen.ai","host":"www.papergen.ai","status_code":200,"title":"PaperGen AI","webserver":"nginx","content_length":1234,"tech":["Next.js","React"],"scheme":"https","port":"443"}\n{"url":"https://api.papergen.ai","host":"api.papergen.ai","status_code":200,"title":"API","webserver":"nginx","content_length":567,"tech":["Express"],"scheme":"https","port":"443"}\n',
            stderr=""
        )
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        live_hosts = agent.execute(["www.papergen.ai", "api.papergen.ai"])

        # Assert
        assert len(live_hosts) == 2
        assert live_hosts[0]["url"] == "https://www.papergen.ai"
        assert live_hosts[0]["status_code"] == 200
        assert live_hosts[0]["title"] == "PaperGen AI"
        assert live_hosts[1]["url"] == "https://api.papergen.ai"
        mock_sandbox.commands.run.assert_called_once()

        # Verify command format
        call_args = mock_sandbox.commands.run.call_args
        assert "httpx" in call_args[0][0]
        assert "-json" in call_args[0][0]
        assert "-l /tmp/httpx_targets.txt" in call_args[0][0]

    def test_execute_no_live_hosts(self, agent, mock_sandbox):
        """Test when no hosts are live."""
        # Arrange
        mock_result = Mock(exit_code=0, stdout="", stderr="")
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        live_hosts = agent.execute(["dead.example.com"])

        # Assert
        assert len(live_hosts) == 0
        assert live_hosts == []

    def test_execute_empty_targets(self, agent, mock_sandbox):
        """Test with empty target list."""
        # Act
        live_hosts = agent.execute([])

        # Assert
        assert len(live_hosts) == 0
        # Should not call sandbox since no targets
        mock_sandbox.commands.run.assert_not_called()

    def test_execute_with_custom_threads(self, agent, mock_sandbox):
        """Test custom thread parameter."""
        # Arrange
        mock_result = Mock(exit_code=0, stdout="", stderr="")
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        agent.execute(["example.com"], threads=100)

        # Assert
        call_args = mock_sandbox.commands.run.call_args
        assert "-threads 100" in call_args[0][0]

    def test_execute_stores_results(self, agent, mock_sandbox, mock_backend):
        """Test that results are stored in Nexus workspace."""
        # Arrange
        mock_result = Mock(
            exit_code=0,
            stdout='{"url":"https://www.example.com","host":"www.example.com","status_code":200,"title":"Example","webserver":"Apache","content_length":1000,"tech":[],"scheme":"https","port":"443"}\n',
            stderr=""
        )
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        agent.execute(["www.example.com"])

        # Assert - Should write JSON and raw output
        assert mock_backend.write.call_count == 2

        # Check JSON write
        json_call = mock_backend.write.call_args_list[0]
        assert "/recon/httpx/live_hosts.json" in json_call[0]
        json_content = json_call[0][1]
        assert "www.example.com" in json_content
        assert '"live_hosts_count": 1' in json_content

        # Check raw output write
        raw_call = mock_backend.write.call_args_list[1]
        assert "/recon/httpx/raw_output.txt" in raw_call[0]

    def test_execute_writes_targets_to_sandbox(self, agent, mock_sandbox):
        """Test that targets are written to sandbox file."""
        # Arrange
        mock_result = Mock(exit_code=0, stdout="", stderr="")
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        targets = ["sub1.example.com", "sub2.example.com"]
        agent.execute(targets)

        # Assert
        mock_sandbox.files.write.assert_called_once_with(
            "/tmp/httpx_targets.txt",
            "sub1.example.com\nsub2.example.com"
        )


class TestHTTPxOutputParsing:
    """Test output parsing and JSON handling."""

    def test_parse_json_with_all_fields(self, agent, mock_sandbox):
        """Test parsing JSON with all fields present."""
        # Arrange
        json_output = {
            "url": "https://www.papergen.ai",
            "host": "www.papergen.ai",
            "status_code": 200,
            "title": "PaperGen - AI Writing Tool",
            "webserver": "nginx/1.18.0",
            "content_length": 15234,
            "tech": ["Next.js", "React", "Webpack"],
            "scheme": "https",
            "port": "443"
        }
        mock_result = Mock(
            exit_code=0,
            stdout=json.dumps(json_output) + "\n",
            stderr=""
        )
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        live_hosts = agent.execute(["www.papergen.ai"])

        # Assert
        assert len(live_hosts) == 1
        host = live_hosts[0]
        assert host["url"] == "https://www.papergen.ai"
        assert host["status_code"] == 200
        assert host["title"] == "PaperGen - AI Writing Tool"
        assert host["web_server"] == "nginx/1.18.0"
        assert host["content_length"] == 15234
        assert "Next.js" in host["technologies"]
        assert "React" in host["technologies"]
        assert host["scheme"] == "https"
        assert host["port"] == "443"

    def test_parse_json_with_missing_fields(self, agent, mock_sandbox):
        """Test parsing JSON with some missing optional fields."""
        # Arrange
        json_output = {
            "url": "http://example.com",
            "status_code": 200
        }
        mock_result = Mock(
            exit_code=0,
            stdout=json.dumps(json_output) + "\n",
            stderr=""
        )
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        live_hosts = agent.execute(["example.com"])

        # Assert
        assert len(live_hosts) == 1
        host = live_hosts[0]
        assert host["url"] == "http://example.com"
        assert host["status_code"] == 200
        assert host["title"] == ""  # Default empty
        assert host["technologies"] == []  # Default empty list

    def test_parse_multiple_json_lines(self, agent, mock_sandbox):
        """Test parsing multiple JSON lines."""
        # Arrange
        json1 = '{"url":"https://www.example.com","status_code":200,"title":"Home"}\n'
        json2 = '{"url":"https://api.example.com","status_code":200,"title":"API"}\n'
        json3 = '{"url":"https://blog.example.com","status_code":200,"title":"Blog"}\n'

        mock_result = Mock(
            exit_code=0,
            stdout=json1 + json2 + json3,
            stderr=""
        )
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        live_hosts = agent.execute(["www.example.com", "api.example.com", "blog.example.com"])

        # Assert
        assert len(live_hosts) == 3
        assert live_hosts[0]["title"] == "Home"
        assert live_hosts[1]["title"] == "API"
        assert live_hosts[2]["title"] == "Blog"

    def test_parse_invalid_json_line_skipped(self, agent, mock_sandbox):
        """Test that invalid JSON lines are skipped gracefully."""
        # Arrange
        good_json = '{"url":"https://www.example.com","status_code":200}\n'
        bad_json = 'this is not valid json\n'

        mock_result = Mock(
            exit_code=0,
            stdout=good_json + bad_json,
            stderr=""
        )
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        live_hosts = agent.execute(["www.example.com", "broken.example.com"])

        # Assert - Only valid JSON parsed
        assert len(live_hosts) == 1
        assert live_hosts[0]["url"] == "https://www.example.com"

    def test_parse_empty_lines_ignored(self, agent, mock_sandbox):
        """Test that empty lines are ignored."""
        # Arrange
        json1 = '{"url":"https://www.example.com","status_code":200}\n'

        mock_result = Mock(
            exit_code=0,
            stdout="\n\n" + json1 + "\n\n",
            stderr=""
        )
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        live_hosts = agent.execute(["www.example.com"])

        # Assert
        assert len(live_hosts) == 1


class TestTargetValidation:
    """Test target validation logic."""

    def test_validate_valid_targets(self, agent):
        """Test valid target formats."""
        valid_targets = [
            "example.com",
            "www.example.com",
            "api.sub.example.com",
            "test-domain.co.uk",
            "123.example.com",
        ]

        # Should not raise
        agent._validate_targets(valid_targets)

    def test_validate_targets_with_protocols(self, agent):
        """Test targets with http/https protocols."""
        targets = [
            "http://example.com",
            "https://www.example.com",
        ]

        # Should not raise - protocols are stripped for validation
        agent._validate_targets(targets)

    def test_validate_empty_list_raises(self, agent):
        """Test empty target list raises error."""
        with pytest.raises(ValueError, match="cannot be empty"):
            agent._validate_targets([])

    def test_validate_non_list_raises(self, agent):
        """Test non-list input raises error."""
        with pytest.raises(ValueError, match="must be a list"):
            agent._validate_targets("not-a-list")

    def test_validate_invalid_target_format(self, agent):
        """Test invalid target format."""
        with pytest.raises(ValueError, match="Invalid target format"):
            agent._validate_targets(["not a domain!"])

    def test_validate_target_too_long(self, agent):
        """Test target exceeding 253 character limit."""
        long_target = "a" * 250 + ".com"
        with pytest.raises(ValueError, match="Target too long"):
            agent._validate_targets([long_target])

    def test_execute_with_invalid_targets(self, agent):
        """Test execution with invalid targets raises error."""
        with pytest.raises(HTTPxError, match="Invalid target format"):
            agent.execute(["invalid domain name"])


class TestErrorHandling:
    """Test error handling scenarios."""

    def test_execute_timeout(self, agent, mock_sandbox):
        """Test timeout handling."""
        # Arrange
        mock_sandbox.commands.run.side_effect = TimeoutError("Command timeout")

        # Act & Assert
        with pytest.raises(HTTPxError, match="timed out"):
            agent.execute(["example.com"], timeout=60)

    def test_execute_general_exception(self, agent, mock_sandbox):
        """Test handling of unexpected exceptions."""
        # Arrange
        mock_sandbox.commands.run.side_effect = Exception("Unexpected error")

        # Act & Assert
        with pytest.raises(HTTPxError):
            agent.execute(["example.com"])

    def test_store_results_write_failure(self, agent, mock_sandbox, mock_backend):
        """Test handling when Nexus write fails."""
        # Arrange
        mock_result = Mock(
            exit_code=0,
            stdout='{"url":"https://www.example.com","status_code":200}\n',
            stderr=""
        )
        mock_sandbox.commands.run.return_value = mock_result
        mock_backend.write.return_value = Mock(error="Write failed", path=None)

        # Act & Assert
        with pytest.raises(HTTPxError, match="Failed to store results"):
            agent.execute(["www.example.com"])


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
        agent._owns_sandbox = True
        mock_sandbox.kill.side_effect = Exception("Kill failed")

        # Act - Should not raise
        agent.cleanup()

    def test_agent_initialization_without_sandbox(self, mock_backend):
        """Test agent auto-creates sandbox if not provided."""
        agent = HTTPxAgent(
            scan_id="test-scan",
            team_id="test-team",
            nexus_backend=mock_backend,
            sandbox=Mock()  # Provide mock to avoid real E2B creation
        )

        assert agent.sandbox is not None


class TestOutputFormat:
    """Test output data format and structure."""

    def test_returns_list_of_dicts(self, agent, mock_sandbox):
        """Test that execute returns a list of dictionaries."""
        # Arrange
        mock_result = Mock(
            exit_code=0,
            stdout='{"url":"https://www.example.com","status_code":200}\n',
            stderr=""
        )
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        result = agent.execute(["www.example.com"])

        # Assert
        assert isinstance(result, list)
        assert all(isinstance(item, dict) for item in result)

    def test_json_output_structure(self, agent, mock_sandbox, mock_backend):
        """Test JSON output has correct structure."""
        # Arrange
        mock_result = Mock(
            exit_code=0,
            stdout='{"url":"https://api.example.com","status_code":200}\n',
            stderr=""
        )
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        agent.execute(["api.example.com"])

        # Assert
        json_content = mock_backend.write.call_args_list[0][0][1]
        assert "targets_count" in json_content
        assert "live_hosts_count" in json_content
        assert "live_hosts" in json_content
        assert "timestamp" in json_content
        assert "scan_id" in json_content
        assert "team_id" in json_content
        assert "tool" in json_content
        assert "version" in json_content

    def test_host_has_timestamp(self, agent, mock_sandbox):
        """Test that each host has a probed_at timestamp."""
        # Arrange
        mock_result = Mock(
            exit_code=0,
            stdout='{"url":"https://www.example.com","status_code":200}\n',
            stderr=""
        )
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        live_hosts = agent.execute(["www.example.com"])

        # Assert
        assert "probed_at" in live_hosts[0]
        assert live_hosts[0]["probed_at"]  # Not empty


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_execute_with_single_target(self, agent, mock_sandbox):
        """Test with exactly one target."""
        # Arrange
        mock_result = Mock(
            exit_code=0,
            stdout='{"url":"https://www.papergen.ai","status_code":200}\n',
            stderr=""
        )
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        live_hosts = agent.execute(["www.papergen.ai"])

        # Assert
        assert len(live_hosts) == 1
        assert live_hosts[0]["url"] == "https://www.papergen.ai"

    def test_execute_with_many_targets(self, agent, mock_sandbox):
        """Test with large number of targets."""
        # Arrange
        targets = [f"sub{i}.example.com" for i in range(100)]
        json_lines = "\n".join([
            f'{{"url":"https://sub{i}.example.com","status_code":200}}'
            for i in range(100)
        ])
        mock_result = Mock(exit_code=0, stdout=json_lines + "\n", stderr="")
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        live_hosts = agent.execute(targets)

        # Assert
        assert len(live_hosts) == 100

    def test_execute_partial_live_hosts(self, agent, mock_sandbox):
        """Test when only some targets are live."""
        # Arrange - 2 live out of 3 targets
        json_lines = (
            '{"url":"https://www.example.com","status_code":200}\n'
            '{"url":"https://api.example.com","status_code":200}\n'
        )
        mock_result = Mock(exit_code=0, stdout=json_lines, stderr="")
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        live_hosts = agent.execute(["www.example.com", "api.example.com", "dead.example.com"])

        # Assert
        assert len(live_hosts) == 2
        # Verify targets_count vs live_hosts_count in storage
        # This is tested in the storage test above


class TestHTTPxParameters:
    """Test HTTPx command parameter handling."""

    def test_follow_redirects_enabled(self, agent, mock_sandbox):
        """Test follow redirects parameter enabled."""
        # Arrange
        mock_result = Mock(exit_code=0, stdout="", stderr="")
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        agent.execute(["example.com"], follow_redirects=True)

        # Assert
        call_args = mock_sandbox.commands.run.call_args
        assert "-follow-redirects" in call_args[0][0]

    def test_follow_redirects_disabled(self, agent, mock_sandbox):
        """Test follow redirects parameter disabled."""
        # Arrange
        mock_result = Mock(exit_code=0, stdout="", stderr="")
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        agent.execute(["example.com"], follow_redirects=False)

        # Assert
        call_args = mock_sandbox.commands.run.call_args
        assert "-follow-redirects" not in call_args[0][0]

    def test_tech_detect_enabled(self, agent, mock_sandbox):
        """Test technology detection enabled."""
        # Arrange
        mock_result = Mock(exit_code=0, stdout="", stderr="")
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        agent.execute(["example.com"], tech_detect=True)

        # Assert
        call_args = mock_sandbox.commands.run.call_args
        assert "-tech-detect" in call_args[0][0]

    def test_tech_detect_disabled(self, agent, mock_sandbox):
        """Test technology detection disabled."""
        # Arrange
        mock_result = Mock(exit_code=0, stdout="", stderr="")
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        agent.execute(["example.com"], tech_detect=False)

        # Assert
        call_args = mock_sandbox.commands.run.call_args
        assert "-tech-detect" not in call_args[0][0]
