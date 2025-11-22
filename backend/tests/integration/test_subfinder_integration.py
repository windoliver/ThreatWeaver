"""
Integration tests for SubfinderAgent with real E2B sandbox.

These tests require:
1. E2B_API_KEY environment variable
2. E2B template access (template must be public or API key must match template owner)

Run:
    export E2B_API_KEY=your_key_here
    pytest tests/integration/test_subfinder_integration.py -v -m integration

Skip if E2B not available:
    pytest tests/ -v -m "not integration"
"""

import os
import pytest

from e2b import Sandbox

from src.agents.recon.subfinder_agent import SubfinderAgent, SubfinderError
from src.agents.backends.nexus_backend import NexusBackend
from src.config import get_nexus_fs


# Skip all tests if E2B_API_KEY not set
pytestmark = pytest.mark.skipif(
    not os.getenv("E2B_API_KEY"),
    reason="E2B_API_KEY not set - skipping integration tests"
)


@pytest.fixture(scope="module")
def e2b_sandbox():
    """Create real E2B sandbox with threatweaver-security template."""
    try:
        sandbox = Sandbox.create(template="dbe6pq4es6hqj31ybd38")
        yield sandbox
        sandbox.kill()
    except Exception as e:
        pytest.skip(f"Failed to create E2B sandbox: {e}")


@pytest.fixture
def integration_workspace(tmp_path):
    """Create temporary Nexus workspace for integration tests."""
    nx = get_nexus_fs()
    backend = NexusBackend(
        scan_id="test-integration-scan",
        team_id="test-integration-team",
        nexus_fs=nx
    )
    return backend


@pytest.fixture
def real_agent(e2b_sandbox, integration_workspace):
    """Create SubfinderAgent with real E2B sandbox."""
    agent = SubfinderAgent(
        scan_id="test-integration-scan",
        team_id="test-integration-team",
        nexus_backend=integration_workspace,
        sandbox=e2b_sandbox
    )
    return agent


@pytest.mark.integration
@pytest.mark.slow
class TestSubfinderIntegration:
    """Integration tests with real E2B sandbox and Subfinder."""

    def test_subfinder_tool_availability(self, e2b_sandbox):
        """Verify Subfinder is installed in E2B template."""
        # Act
        result = e2b_sandbox.commands.run("subfinder -version")

        # Assert
        assert result.exit_code == 0
        # Subfinder outputs version to stderr
        output = (result.stdout + result.stderr).lower()
        assert "version" in output or "subfinder" in output

    def test_real_subfinder_execution(self, real_agent):
        """Test Subfinder execution with real E2B sandbox."""
        # Act - Use a well-known domain with predictable subdomains
        subdomains = real_agent.execute("google.com", timeout=120)

        # Assert
        assert len(subdomains) > 0, "Should find at least some subdomains"
        assert any("google.com" in sub for sub in subdomains), "Subdomains should contain google.com"

        print(f"\n✅ Found {len(subdomains)} subdomains for google.com")
        print(f"Sample: {subdomains[:5]}")

    def test_results_persist_to_nexus(self, real_agent, integration_workspace):
        """Test that results are actually written to Nexus workspace."""
        # Act
        real_agent.execute("github.com", timeout=120)

        # Assert - Check workspace has the files
        files = integration_workspace.get_all_files()
        assert "recon/subfinder/subdomains.json" in files, "JSON results should exist"
        assert "recon/subfinder/raw_output.txt" in files, "Raw output should exist"

        # Verify JSON structure
        json_content = files["recon/subfinder/subdomains.json"]
        assert "domain" in json_content
        assert "github.com" in json_content
        assert "subdomains" in json_content
        assert "count" in json_content

    def test_multiple_domains_sequential(self, real_agent):
        """Test scanning multiple domains sequentially."""
        # Act
        domains = ["github.com", "gitlab.com"]
        results = {}

        for domain in domains:
            results[domain] = real_agent.execute(domain, timeout=120)

        # Assert
        assert len(results) == 2
        assert all(len(subs) > 0 for subs in results.values()), "All domains should have subdomains"

        print(f"\n✅ Sequential scan results:")
        for domain, subs in results.items():
            print(f"  {domain}: {len(subs)} subdomains")

    def test_timeout_enforcement(self, real_agent):
        """Test that timeout is enforced for slow scans."""
        # This test uses a very short timeout to trigger timeout behavior
        # Note: May not always trigger timeout depending on Subfinder speed

        with pytest.raises(SubfinderError, match="(timed out|deadline exceeded)"):
            # Use 1 second timeout - almost guaranteed to timeout
            real_agent.execute("example.com", timeout=1)

    def test_wildcard_filtering(self, real_agent):
        """Test wildcard filtering with real results."""
        # Act
        subdomains_filtered = real_agent.execute("example.com", filter_wildcards=True)
        subdomains_unfiltered = real_agent.execute("example.com", filter_wildcards=False)

        # Assert
        assert all(not sub.startswith("*") for sub in subdomains_filtered), \
            "Filtered results should have no wildcards"

        print(f"\n✅ Wildcard filtering:")
        print(f"  Filtered: {len(subdomains_filtered)} subdomains")
        print(f"  Unfiltered: {len(subdomains_unfiltered)} subdomains")

    def test_invalid_domain_handling(self, real_agent):
        """Test error handling with invalid domain."""
        # Act & Assert
        with pytest.raises(SubfinderError, match="Invalid domain format"):
            real_agent.execute("not a valid domain!", timeout=60)

    def test_no_results_domain(self, real_agent):
        """Test handling of domain with no subdomains."""
        # Use a domain unlikely to have subdomains
        subdomains = real_agent.execute("thisisanonexistentdomainforsure.com", timeout=60)

        # Assert - Should return empty list, not error
        assert isinstance(subdomains, list)
        print(f"\n✅ No results test: {len(subdomains)} subdomains found")


@pytest.mark.integration
@pytest.mark.slow
class TestE2BTemplateVerification:
    """Verify E2B template has all required tools."""

    def test_all_security_tools_present(self, e2b_sandbox):
        """Verify all security tools are installed in template."""
        tools = {
            "subfinder": "subfinder -version",
            "httpx": "httpx -version",
            "nuclei": "nuclei -version",
            "nmap": "nmap --version",
            "sqlmap": "python3 /opt/sqlmap/sqlmap.py --version"
        }

        results = {}
        for tool_name, command in tools.items():
            result = e2b_sandbox.commands.run(command)
            results[tool_name] = result.exit_code == 0

        # Assert all tools available
        missing_tools = [name for name, available in results.items() if not available]
        assert not missing_tools, f"Missing tools: {missing_tools}"

        print("\n✅ All security tools verified:")
        for tool in results.keys():
            print(f"  ✓ {tool}")

    def test_template_environment(self, e2b_sandbox):
        """Verify template environment setup."""
        # Check Python availability
        result = e2b_sandbox.commands.run("python3 --version")
        assert result.exit_code == 0

        # Check workspace directory
        result = e2b_sandbox.commands.run("ls -la /workspace")
        assert result.exit_code == 0

        print("\n✅ Template environment verified")


@pytest.mark.integration
class TestE2BAccessIssue:
    """Test to diagnose E2B template access issues."""

    def test_template_access_diagnosis(self):
        """Diagnostic test for E2B template access issues."""
        try:
            # Try to create sandbox with template
            sandbox = Sandbox.create(template="dbe6pq4es6hqj31ybd38")

            # If we get here, access is working
            sandbox.kill()
            print("\n✅ E2B template access is working!")

        except Exception as e:
            error_msg = str(e)

            if "403" in error_msg or "does not have access" in error_msg:
                pytest.fail(
                    "\n❌ E2B Template Access Issue Detected!\n"
                    "\n"
                    "Error: 403 - Team does not have access to template\n"
                    "\n"
                    "Solutions:\n"
                    "1. Make template public:\n"
                    "   - Go to https://e2b.dev/dashboard\n"
                    "   - Find template 'threatweaver-security' (dbe6pq4es6hqj31ybd38)\n"
                    "   - Change visibility to 'Public'\n"
                    "\n"
                    "2. Use correct API key:\n"
                    "   - Get API key from team that owns the template\n"
                    "   - Update E2B_API_KEY environment variable\n"
                    "\n"
                    "3. Rebuild template with your team:\n"
                    "   cd e2b-template\n"
                    "   e2b template build -t your-team-id\n"
                )
            else:
                pytest.fail(f"\n❌ E2B Error: {error_msg}")
