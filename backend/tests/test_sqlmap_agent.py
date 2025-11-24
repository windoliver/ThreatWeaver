"""
Unit tests for SQLMapAgent.

These tests use mocks to avoid E2B sandbox dependency.
For E2B integration tests, see tests/integration/test_sqlmap_e2e.py
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime

from src.agents.assessment.sqlmap_agent import (
    SQLMapAgent,
    SQLMapFinding,
    SQLMapError,
    SQLMapLevel,
    SQLMapRisk,
)


@pytest.fixture
def mock_sandbox():
    """Create a mock E2B sandbox."""
    sandbox = Mock()
    sandbox.commands = Mock()
    sandbox.files = Mock()
    return sandbox


@pytest.fixture
def mock_backend():
    """Create a mock NexusBackend."""
    backend = Mock()
    backend.write = Mock(return_value=Mock(error=None))
    backend.read = Mock(return_value="")
    backend.edit = Mock(return_value=Mock(error=None))
    return backend


@pytest.fixture
def sqlmap_agent(mock_sandbox, mock_backend):
    """Create SQLMapAgent with mocked dependencies."""
    agent = SQLMapAgent(
        scan_id="test-scan-123",
        team_id="test-team",
        nexus_backend=mock_backend,
        sandbox=mock_sandbox
    )
    return agent


class TestSQLMapAgentInit:
    """Test SQLMapAgent initialization."""

    def test_init_with_provided_sandbox(self, mock_sandbox, mock_backend):
        """Test initialization with provided sandbox."""
        agent = SQLMapAgent(
            scan_id="test",
            team_id="team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox
        )

        assert agent.scan_id == "test"
        assert agent.team_id == "team"
        assert agent.sandbox == mock_sandbox
        assert agent._owns_sandbox is False

    @patch("src.agents.assessment.sqlmap_agent.Sandbox")
    def test_init_creates_sandbox(self, mock_sandbox_class, mock_backend):
        """Test that sandbox is auto-created if not provided."""
        mock_sandbox_class.create.return_value = Mock()

        agent = SQLMapAgent(
            scan_id="test",
            team_id="team",
            nexus_backend=mock_backend
        )

        assert agent._owns_sandbox is True
        mock_sandbox_class.create.assert_called_once_with(
            template="dbe6pq4es6hqj31ybd38"
        )


class TestSQLMapAgentValidation:
    """Test input validation."""

    def test_validate_empty_url(self, sqlmap_agent):
        """Test that empty URL raises ValueError."""
        # ValueError is raised before being wrapped in SQLMapError
        with pytest.raises(ValueError, match="cannot be empty"):
            sqlmap_agent.execute(target_url="")

    def test_validate_url_without_protocol(self, sqlmap_agent):
        """Test that URL without protocol raises ValueError."""
        # ValueError is raised before being wrapped in SQLMapError
        with pytest.raises(ValueError, match="must be a full URL with protocol"):
            sqlmap_agent.execute(target_url="example.com/page?id=1")

    def test_validate_url_with_http(self, sqlmap_agent, mock_sandbox):
        """Test that http:// URLs are accepted."""
        mock_sandbox.commands.run.return_value = Mock(
            stdout="",
            stderr="",
            exit_code=0
        )

        # Should not raise
        result = sqlmap_agent.execute(target_url="http://example.com/page?id=1")
        assert isinstance(result, list)

    def test_validate_url_with_https(self, sqlmap_agent, mock_sandbox):
        """Test that https:// URLs are accepted."""
        mock_sandbox.commands.run.return_value = Mock(
            stdout="",
            stderr="",
            exit_code=0
        )

        # Should not raise
        result = sqlmap_agent.execute(target_url="https://example.com/page?id=1")
        assert isinstance(result, list)


class TestSQLMapAgentExecution:
    """Test SQLMap execution."""

    def test_execute_builds_correct_command(self, sqlmap_agent, mock_sandbox):
        """Test that execute builds the correct SQLMap command."""
        mock_sandbox.commands.run.return_value = Mock(
            stdout="",
            stderr="",
            exit_code=0
        )

        sqlmap_agent.execute(
            target_url="https://example.com/page?id=1",
            level=3,
            risk=2,
            timeout=600
        )

        # Check command was called
        call_args = mock_sandbox.commands.run.call_args
        command = call_args[0][0]

        assert "sqlmap" in command
        assert "-u 'https://example.com/page?id=1'" in command
        assert "--level=3" in command
        assert "--risk=2" in command
        assert "--batch" in command
        assert "--random-agent" in command

    def test_execute_with_post_data(self, sqlmap_agent, mock_sandbox):
        """Test execution with POST data."""
        mock_sandbox.commands.run.return_value = Mock(
            stdout="",
            stderr="",
            exit_code=0
        )

        sqlmap_agent.execute(
            target_url="https://example.com/login",
            data="username=test&password=test123"
        )

        call_args = mock_sandbox.commands.run.call_args
        command = call_args[0][0]

        assert "--data='username=test&password=test123'" in command

    def test_execute_with_cookie(self, sqlmap_agent, mock_sandbox):
        """Test execution with cookie."""
        mock_sandbox.commands.run.return_value = Mock(
            stdout="",
            stderr="",
            exit_code=0
        )

        sqlmap_agent.execute(
            target_url="https://example.com/page?id=1",
            cookie="session=abc123"
        )

        call_args = mock_sandbox.commands.run.call_args
        command = call_args[0][0]

        assert "--cookie='session=abc123'" in command

    def test_execute_with_tamper_scripts(self, sqlmap_agent, mock_sandbox):
        """Test execution with tamper scripts."""
        mock_sandbox.commands.run.return_value = Mock(
            stdout="",
            stderr="",
            exit_code=0
        )

        sqlmap_agent.execute(
            target_url="https://example.com/page?id=1",
            tamper=["space2comment", "between"]
        )

        call_args = mock_sandbox.commands.run.call_args
        command = call_args[0][0]

        assert "--tamper=space2comment,between" in command

    def test_execute_enforces_max_timeout(self, sqlmap_agent, mock_sandbox):
        """Test that timeout is capped at 3600 seconds."""
        mock_sandbox.commands.run.return_value = Mock(
            stdout="",
            stderr="",
            exit_code=0
        )

        # Try to set timeout > 3600
        sqlmap_agent.execute(
            target_url="https://example.com/page?id=1",
            timeout=7200  # 2 hours
        )

        # Verify timeout was capped at 3600
        call_args = mock_sandbox.commands.run.call_args
        assert call_args[1]["timeout"] == 3600

    def test_execute_enforces_level_bounds(self, sqlmap_agent, mock_sandbox):
        """Test that level is bounded 1-5."""
        mock_sandbox.commands.run.return_value = Mock(
            stdout="",
            stderr="",
            exit_code=0
        )

        # Test level > 5
        sqlmap_agent.execute(
            target_url="https://example.com/page?id=1",
            level=10
        )

        call_args = mock_sandbox.commands.run.call_args
        command = call_args[0][0]
        assert "--level=5" in command

    def test_execute_enforces_risk_bounds(self, sqlmap_agent, mock_sandbox):
        """Test that risk is bounded 1-3."""
        mock_sandbox.commands.run.return_value = Mock(
            stdout="",
            stderr="",
            exit_code=0
        )

        # Test risk > 3
        sqlmap_agent.execute(
            target_url="https://example.com/page?id=1",
            risk=5
        )

        call_args = mock_sandbox.commands.run.call_args
        command = call_args[0][0]
        assert "--risk=3" in command


class TestSQLMapOutputParsing:
    """Test SQLMap output parsing."""

    def test_parse_no_injection_found(self, sqlmap_agent):
        """Test parsing when no injection is found."""
        # Output without "injectable" or "vulnerable" keywords
        output = """
        [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
        [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
        [INFO] testing connection to the target URL
        [WARNING] 'id' does not appear to be susceptible to injection
        [INFO] testing if the target URL is stable
        [INFO] all tested parameters appear to be not affected
        """

        findings = sqlmap_agent._parse_output(
            "https://example.com/page?id=1",
            output
        )

        assert len(findings) == 0

    def test_parse_injection_found(self, sqlmap_agent):
        """Test parsing when injection is found."""
        output = """
        [INFO] the back-end DBMS is MySQL
        back-end DBMS: MySQL >= 5.0
        Parameter: id (GET)
            Type: boolean-based blind
            Title: AND boolean-based blind - WHERE or HAVING clause
            Payload: id=1' AND 5234=5234 AND 'aXDQ'='aXDQ
        available databases [5]:
        [*] information_schema
        [*] mysql
        [*] test_db
        [*] users_db
        [*] performance_schema
        """

        findings = sqlmap_agent._parse_output(
            "https://example.com/page?id=1",
            output
        )

        assert len(findings) >= 1
        finding = findings[0]
        assert finding.parameter == "id"
        assert finding.injection_type == "boolean-based blind"
        assert "MySQL" in finding.dbms
        assert "test_db" in finding.databases
        assert "users_db" in finding.databases

    def test_parse_multiple_injection_types(self, sqlmap_agent):
        """Test parsing multiple injection types."""
        output = """
        Parameter: id (GET)
            Type: boolean-based blind
            Title: AND boolean-based blind - WHERE or HAVING clause
            Payload: id=1' AND 5234=5234--

        Parameter: name (POST)
            Type: time-based blind
            Title: MySQL >= 5.0.12 AND time-based blind
            Payload: name=test' AND SLEEP(5)--

        back-end DBMS: MySQL >= 5.0
        """

        findings = sqlmap_agent._parse_output(
            "https://example.com/page?id=1",
            output
        )

        assert len(findings) == 2
        params = [f.parameter for f in findings]
        assert "id" in params
        assert "name" in params

    def test_parse_current_user_and_db(self, sqlmap_agent):
        """Test parsing current user and database info."""
        output = """
        Parameter: id (GET)
            Type: UNION query
            Title: Generic UNION query (NULL) - 3 columns

        back-end DBMS: MySQL >= 5.0
        current user: 'root@localhost'
        current database: 'webapp_db'
        current user is DBA: True
        """

        findings = sqlmap_agent._parse_output(
            "https://example.com/page?id=1",
            output
        )

        assert len(findings) >= 1
        finding = findings[0]
        assert finding.current_user == "root@localhost"
        assert finding.current_db == "webapp_db"
        assert finding.is_dba is True


class TestSQLMapResultStorage:
    """Test result storage in Nexus."""

    def test_store_results_writes_json(self, sqlmap_agent, mock_backend, mock_sandbox):
        """Test that results are written to Nexus."""
        mock_sandbox.commands.run.return_value = Mock(
            stdout="[INFO] testing complete",
            stderr="",
            exit_code=0
        )

        sqlmap_agent.execute(target_url="https://example.com/page?id=1")

        # Verify write was called for findings.json
        mock_backend.write.assert_called()
        call_args_list = mock_backend.write.call_args_list

        json_call = None
        for call in call_args_list:
            if "findings.json" in call[0][0]:
                json_call = call
                break

        assert json_call is not None
        json_content = json_call[0][1]
        assert "target_url" in json_content
        assert "vulnerable" in json_content

    def test_store_results_writes_raw_output(self, sqlmap_agent, mock_backend, mock_sandbox):
        """Test that raw output is stored."""
        raw_output = "[INFO] testing 'AND boolean-based blind'"
        mock_sandbox.commands.run.return_value = Mock(
            stdout=raw_output,
            stderr="",
            exit_code=0
        )

        sqlmap_agent.execute(target_url="https://example.com/page?id=1")

        # Verify raw output was written
        call_args_list = mock_backend.write.call_args_list

        raw_call = None
        for call in call_args_list:
            if "raw_output.txt" in call[0][0]:
                raw_call = call
                break

        assert raw_call is not None


class TestSQLMapEnumeration:
    """Test database enumeration methods."""

    def test_enumerate_databases(self, sqlmap_agent, mock_sandbox):
        """Test database enumeration."""
        mock_sandbox.commands.run.return_value = Mock(
            stdout="""
            available databases [3]:
            [*] information_schema
            [*] mysql
            [*] webapp
            """,
            stderr="",
            exit_code=0
        )

        databases = sqlmap_agent.enumerate_databases(
            "https://example.com/page?id=1"
        )

        assert "information_schema" in databases
        assert "mysql" in databases
        assert "webapp" in databases

    def test_enumerate_tables(self, sqlmap_agent, mock_sandbox):
        """Test table enumeration."""
        mock_sandbox.commands.run.return_value = Mock(
            stdout="""
            Database: webapp
            [3 tables]
            +----------+
            | users    |
            | orders   |
            | products |
            +----------+
            """,
            stderr="",
            exit_code=0
        )

        tables = sqlmap_agent.enumerate_tables(
            "https://example.com/page?id=1",
            database="webapp"
        )

        assert "users" in tables
        assert "orders" in tables
        assert "products" in tables


class TestSQLMapCleanup:
    """Test cleanup behavior."""

    def test_cleanup_kills_owned_sandbox(self, mock_sandbox, mock_backend):
        """Test that cleanup kills owned sandbox."""
        agent = SQLMapAgent(
            scan_id="test",
            team_id="team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox
        )
        agent._owns_sandbox = True

        agent.cleanup()

        mock_sandbox.kill.assert_called_once()

    def test_cleanup_does_not_kill_shared_sandbox(self, mock_sandbox, mock_backend):
        """Test that cleanup doesn't kill shared sandbox."""
        agent = SQLMapAgent(
            scan_id="test",
            team_id="team",
            nexus_backend=mock_backend,
            sandbox=mock_sandbox
        )
        agent._owns_sandbox = False

        agent.cleanup()

        mock_sandbox.kill.assert_not_called()


class TestSQLMapFinding:
    """Test SQLMapFinding model."""

    def test_finding_model_minimal(self):
        """Test SQLMapFinding with minimal data."""
        finding = SQLMapFinding(
            target_url="https://example.com/page?id=1",
            parameter="id",
            injection_type="boolean-based blind"
        )

        assert finding.target_url == "https://example.com/page?id=1"
        assert finding.parameter == "id"
        assert finding.injection_type == "boolean-based blind"
        assert finding.dbms is None
        assert finding.databases is None

    def test_finding_model_full(self):
        """Test SQLMapFinding with all fields."""
        finding = SQLMapFinding(
            target_url="https://example.com/page?id=1",
            parameter="id",
            injection_type="UNION query",
            dbms="MySQL >= 5.0",
            dbms_version="5.7.32",
            payload="1' UNION SELECT 1,2,3--",
            title="Generic UNION query",
            place="GET",
            databases=["webapp", "mysql"],
            current_user="root@localhost",
            current_db="webapp",
            is_dba=True
        )

        assert finding.dbms == "MySQL >= 5.0"
        assert finding.payload == "1' UNION SELECT 1,2,3--"
        assert "webapp" in finding.databases
        assert finding.is_dba is True

    def test_finding_model_serialization(self):
        """Test SQLMapFinding serialization."""
        finding = SQLMapFinding(
            target_url="https://example.com/page?id=1",
            parameter="id",
            injection_type="error-based",
            dbms="PostgreSQL"
        )

        data = finding.model_dump()

        assert isinstance(data, dict)
        assert data["target_url"] == "https://example.com/page?id=1"
        assert data["parameter"] == "id"
        assert data["dbms"] == "PostgreSQL"
