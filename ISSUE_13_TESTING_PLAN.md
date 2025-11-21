# Issue #13 Testing Plan: Subfinder Agent

## Testing Strategy Overview

### Testing Pyramid for Subfinder Agent

```
                    E2E Tests (1-2 tests)
                   /                    \
              Integration Tests (5-8 tests)
             /                              \
        Unit Tests (15-20 tests)
```

## 1. Unit Tests (Fast, No External Dependencies)

### Test Setup: Mock E2B Sandbox

```python
# backend/tests/test_subfinder_agent.py
import pytest
from unittest.mock import Mock, patch, AsyncMock
from src.agents.recon.subfinder_agent import SubfinderAgent
from nexus.core.nexus_fs import NexusFS

@pytest.fixture
def mock_sandbox():
    """Mock E2B sandbox for unit tests."""
    sandbox = Mock()
    sandbox.commands.run = Mock()
    return sandbox

@pytest.fixture
def mock_workspace(tmp_path):
    """Create temporary Nexus workspace."""
    return NexusFS(str(tmp_path / "test_workspace"))

@pytest.fixture
def agent(mock_sandbox, mock_workspace):
    """Create SubfinderAgent with mocked dependencies."""
    agent = SubfinderAgent(workspace=mock_workspace)
    agent.sandbox = mock_sandbox  # Inject mock
    return agent
```

### Unit Test Cases

```python
class TestSubfinderAgent:
    """Unit tests for SubfinderAgent (mocked E2B sandbox)."""

    async def test_execute_success(self, agent, mock_sandbox):
        """Test successful subdomain discovery."""
        # Arrange
        mock_result = Mock(
            exit_code=0,
            stdout="sub1.example.com\nsub2.example.com\nsub3.example.com\n",
            stderr=""
        )
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        subdomains = await agent.execute("example.com")

        # Assert
        assert len(subdomains) == 3
        assert "sub1.example.com" in subdomains
        assert "sub2.example.com" in subdomains
        mock_sandbox.commands.run.assert_called_once_with(
            "subfinder -d example.com -silent"
        )

    async def test_execute_no_results(self, agent, mock_sandbox):
        """Test when no subdomains are found."""
        # Arrange
        mock_result = Mock(exit_code=0, stdout="", stderr="")
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        subdomains = await agent.execute("nonexistent.com")

        # Assert
        assert len(subdomains) == 0

    async def test_execute_with_duplicates(self, agent, mock_sandbox):
        """Test deduplication of subdomains."""
        # Arrange
        mock_result = Mock(
            exit_code=0,
            stdout="sub1.example.com\nsub1.example.com\nsub2.example.com\n",
            stderr=""
        )
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        subdomains = await agent.execute("example.com")

        # Assert
        assert len(subdomains) == 2  # Duplicates removed

    async def test_execute_timeout(self, agent, mock_sandbox):
        """Test timeout handling."""
        # Arrange
        mock_sandbox.commands.run.side_effect = TimeoutError("Command timeout")

        # Act & Assert
        with pytest.raises(SubfinderError, match="Timeout"):
            await agent.execute("example.com", timeout=60)

    async def test_execute_invalid_domain(self, agent, mock_sandbox):
        """Test invalid domain validation."""
        # Act & Assert
        with pytest.raises(ValueError, match="Invalid domain"):
            await agent.execute("not a domain!")

    async def test_results_written_to_workspace(self, agent, mock_sandbox, mock_workspace):
        """Test that results are persisted to Nexus workspace."""
        # Arrange
        mock_result = Mock(
            exit_code=0,
            stdout="sub1.example.com\nsub2.example.com\n",
            stderr=""
        )
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        await agent.execute("example.com")

        # Assert
        results = mock_workspace.read("recon/subfinder/subdomains.json")
        assert results["domain"] == "example.com"
        assert results["count"] == 2
        assert "sub1.example.com" in results["subdomains"]

    async def test_execute_with_wildcard_filter(self, agent, mock_sandbox):
        """Test wildcard DNS filtering."""
        # Arrange
        mock_result = Mock(
            exit_code=0,
            stdout="*.example.com\nsub1.example.com\n*.wildcard.example.com\n",
            stderr=""
        )
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        subdomains = await agent.execute("example.com", filter_wildcards=True)

        # Assert
        assert len(subdomains) == 1
        assert "sub1.example.com" in subdomains
        assert "*.example.com" not in subdomains

    async def test_concurrent_execution(self, agent, mock_sandbox):
        """Test concurrent subdomain discovery for multiple domains."""
        # Arrange
        mock_result = Mock(exit_code=0, stdout="sub1.test.com\n", stderr="")
        mock_sandbox.commands.run.return_value = mock_result

        # Act
        import asyncio
        domains = ["test1.com", "test2.com", "test3.com"]
        results = await asyncio.gather(*[agent.execute(d) for d in domains])

        # Assert
        assert len(results) == 3
        assert mock_sandbox.commands.run.call_count == 3

    async def test_error_handling_sandbox_failure(self, agent, mock_sandbox):
        """Test handling when E2B sandbox fails."""
        # Arrange
        mock_sandbox.commands.run.side_effect = Exception("Sandbox error")

        # Act & Assert
        with pytest.raises(SubfinderError, match="Sandbox execution failed"):
            await agent.execute("example.com")

    async def test_parse_output_with_ansi_codes(self, agent):
        """Test parsing output with ANSI color codes."""
        # Arrange
        raw_output = "\x1b[32msub1.example.com\x1b[0m\n\x1b[32msub2.example.com\x1b[0m\n"

        # Act
        subdomains = agent._parse_subfinder_output(raw_output)

        # Assert
        assert len(subdomains) == 2
        assert "sub1.example.com" in subdomains
        assert "\x1b[32m" not in subdomains[0]  # ANSI codes removed
```

**Unit Test Summary**:
- ✅ Fast (runs in < 1 second)
- ✅ No external dependencies (E2B, network)
- ✅ Tests business logic, error handling, edge cases
- ✅ ~15-20 tests covering all code paths

---

## 2. Integration Tests (Real E2B Sandbox, Real Subfinder)

### Test Setup: Real E2B Sandbox

```python
# backend/tests/integration/test_subfinder_integration.py
import pytest
import os
from src.agents.recon.subfinder_agent import SubfinderAgent
from src.sandbox.factory import SandboxFactory
from nexus.core.nexus_fs import NexusFS

@pytest.fixture(scope="module")
def e2b_sandbox():
    """Create real E2B sandbox (requires E2B_API_KEY)."""
    if not os.getenv("E2B_API_KEY"):
        pytest.skip("E2B_API_KEY not set")

    sandbox = SandboxFactory.create(
        provider="e2b",
        template_id="dbe6pq4es6hqj31ybd38"  # threatweaver-security
    )
    yield sandbox
    sandbox.kill()  # Cleanup

@pytest.fixture
def integration_workspace(tmp_path):
    """Create real Nexus workspace for integration tests."""
    return NexusFS(str(tmp_path / "integration_workspace"))

@pytest.fixture
def real_agent(e2b_sandbox, integration_workspace):
    """Create SubfinderAgent with real E2B sandbox."""
    agent = SubfinderAgent(workspace=integration_workspace)
    agent.sandbox = e2b_sandbox
    return agent
```

### Integration Test Cases

```python
class TestSubfinderIntegration:
    """Integration tests with real E2B sandbox and Subfinder."""

    @pytest.mark.integration
    @pytest.mark.slow
    async def test_real_subfinder_execution(self, real_agent):
        """Test Subfinder execution in real E2B sandbox."""
        # Act
        subdomains = await real_agent.execute("google.com")

        # Assert
        assert len(subdomains) > 0
        assert any("google.com" in sub for sub in subdomains)
        print(f"Found {len(subdomains)} subdomains for google.com")

    @pytest.mark.integration
    async def test_subfinder_tool_availability(self, e2b_sandbox):
        """Verify Subfinder is installed in E2B template."""
        # Act
        result = e2b_sandbox.commands.run("subfinder -version")

        # Assert
        assert result.exit_code == 0
        assert "subfinder" in result.stdout.lower()

    @pytest.mark.integration
    async def test_results_persist_to_nexus(self, real_agent, integration_workspace):
        """Test that results are actually written to Nexus."""
        # Act
        await real_agent.execute("example.com")

        # Assert
        assert integration_workspace.exists("recon/subfinder/subdomains.json")
        results = integration_workspace.read("recon/subfinder/subdomains.json")
        assert "domain" in results
        assert "subdomains" in results
        assert "timestamp" in results

    @pytest.mark.integration
    async def test_multiple_domains_sequential(self, real_agent):
        """Test scanning multiple domains sequentially."""
        # Act
        domains = ["github.com", "gitlab.com"]
        results = {}
        for domain in domains:
            results[domain] = await real_agent.execute(domain)

        # Assert
        assert len(results) == 2
        assert all(len(subs) > 0 for subs in results.values())

    @pytest.mark.integration
    @pytest.mark.slow
    async def test_timeout_enforcement(self, real_agent):
        """Test that timeout is enforced for slow scans."""
        # Act & Assert
        with pytest.raises(SubfinderError, match="Timeout"):
            # Use very short timeout to trigger timeout
            await real_agent.execute("large-domain.com", timeout=5)

    @pytest.mark.integration
    async def test_workspace_versioning(self, real_agent, integration_workspace):
        """Test Nexus workspace versioning for multiple runs."""
        # Act - Run twice
        await real_agent.execute("example.com")
        await real_agent.execute("example.com")

        # Assert - Check version history
        versions = integration_workspace.list_versions("recon/subfinder/subdomains.json")
        assert len(versions) >= 2  # Multiple versions stored
```

**Integration Test Summary**:
- ⏱️ Slower (5-30 seconds per test)
- 🔑 Requires `E2B_API_KEY` environment variable
- 🌐 Makes real network requests to Subfinder
- ✅ Tests real tool behavior and E2B integration
- 📊 ~5-8 tests covering critical paths

---

## 3. End-to-End Tests (Full Workflow)

### E2E Test Setup

```python
# backend/tests/e2e/test_subfinder_e2e.py
import pytest
from src.agents.recon.subfinder_agent import SubfinderAgent
from src.sandbox.factory import SandboxFactory
from nexus.core.nexus_fs import NexusFS

@pytest.mark.e2e
@pytest.mark.slow
class TestSubfinderE2E:
    """End-to-end tests for complete Subfinder workflow."""

    async def test_complete_subdomain_discovery_workflow(self, tmp_path):
        """
        Test complete workflow:
        1. Create workspace
        2. Initialize agent
        3. Discover subdomains
        4. Verify results in Nexus
        5. Cleanup
        """
        # Arrange
        workspace = NexusFS(str(tmp_path / "e2e_workspace"))
        sandbox = SandboxFactory.create("e2b", template_id="dbe6pq4es6hqj31ybd38")
        agent = SubfinderAgent(workspace=workspace)
        agent.sandbox = sandbox

        try:
            # Act
            target = "hackerone.com"
            subdomains = await agent.execute(target)

            # Assert
            assert len(subdomains) > 0
            assert workspace.exists("recon/subfinder/subdomains.json")

            results = workspace.read("recon/subfinder/subdomains.json")
            assert results["domain"] == target
            assert results["count"] == len(subdomains)

            print(f"✅ E2E Test Passed: Found {len(subdomains)} subdomains")

        finally:
            # Cleanup
            sandbox.kill()

    async def test_scan_with_diff_detection(self, tmp_path):
        """
        Test workflow with diff detection:
        1. Run scan #1
        2. Run scan #2
        3. Compare results (new/removed subdomains)
        """
        # Arrange
        workspace = NexusFS(str(tmp_path / "diff_workspace"))
        sandbox = SandboxFactory.create("e2b", template_id="dbe6pq4es6hqj31ybd38")
        agent = SubfinderAgent(workspace=workspace)
        agent.sandbox = sandbox

        try:
            # Act - First scan
            subdomains_v1 = await agent.execute("example.com")

            # Simulate time passing / new subdomains appearing
            # (In real test, would wait or mock data change)

            # Act - Second scan
            subdomains_v2 = await agent.execute("example.com")

            # Assert - Check diff detection
            new_subs = set(subdomains_v2) - set(subdomains_v1)
            removed_subs = set(subdomains_v1) - set(subdomains_v2)

            print(f"New subdomains: {len(new_subs)}")
            print(f"Removed subdomains: {len(removed_subs)}")

        finally:
            sandbox.kill()
```

**E2E Test Summary**:
- 🐌 Slowest (30-60 seconds per test)
- 🌍 Full workflow from start to finish
- ✅ Tests real-world scenarios
- 📊 1-2 critical path tests

---

## 4. Test Execution Strategy

### Local Development

```bash
# 1. Fast feedback loop (unit tests only)
pytest backend/tests/test_subfinder_agent.py -v
# ⚡ Runs in < 1 second

# 2. Integration tests (requires E2B_API_KEY)
export E2B_API_KEY=e2b_your_key_here
pytest backend/tests/integration/test_subfinder_integration.py -m integration -v
# ⏱️ Runs in 30-60 seconds

# 3. Full test suite
pytest backend/tests/ -v
# 📊 Runs all tests
```

### CI/CD Pipeline

```yaml
# .github/workflows/test.yml
name: Test Subfinder Agent

on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run unit tests
        run: pytest backend/tests/test_subfinder_agent.py -v
    # ⚡ Fast, no secrets needed

  integration-tests:
    runs-on: ubuntu-latest
    needs: unit-tests
    steps:
      - uses: actions/checkout@v3
      - name: Run integration tests
        env:
          E2B_API_KEY: ${{ secrets.E2B_API_KEY }}
        run: pytest backend/tests/integration/ -m integration -v
    # 🔑 Requires E2B API key secret

  e2e-tests:
    runs-on: ubuntu-latest
    needs: integration-tests
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v3
      - name: Run E2E tests
        env:
          E2B_API_KEY: ${{ secrets.E2B_API_KEY }}
        run: pytest backend/tests/e2e/ -m e2e -v
    # 🐌 Only on main branch merges
```

---

## 5. Test Data & Fixtures

### Mock Subfinder Outputs

```python
# backend/tests/fixtures/subfinder_outputs.py
MOCK_OUTPUTS = {
    "example.com": """
www.example.com
api.example.com
staging.example.com
dev.example.com
""",
    "no_results.com": "",
    "with_wildcards.com": """
*.cdn.example.com
sub1.example.com
*.wildcard.example.com
sub2.example.com
""",
    "large_output.com": "\n".join([f"sub{i}.example.com" for i in range(1000)])
}
```

### Test Domains

```python
# Use these for integration/E2E tests (safe, predictable)
TEST_DOMAINS = [
    "google.com",        # Many subdomains
    "github.com",        # Well-known, stable
    "hackerone.com",     # Security-focused
    "example.com",       # Minimal subdomains
]
```

---

## 6. Before Running Tests: Resolve E2B Template Access

**Current Blocker**: E2B template is private (403 error)

### Quick Fix (5 minutes):

**Option 1: Make Template Public**
1. Go to https://e2b.dev/dashboard
2. Find `threatweaver-security` template
3. Change to "Public"

**Option 2: Use Correct API Key**
- Get API key from team that owns template
- Update `E2B_API_KEY` in environment

**Option 3: Use Base Template for Testing**
```python
# Temporary: Use base E2B template (no custom tools)
sandbox = SandboxFactory.create("e2b")  # No template_id

# Install Subfinder at runtime (slower but works for testing)
sandbox.commands.run("wget ... && unzip ... && mv subfinder /usr/local/bin/")
```

---

## 7. Test Development Workflow

### Recommended Order

```
Day 1: Unit Tests
├── Write SubfinderAgent skeleton
├── Write 5-10 unit tests (TDD)
├── Implement agent logic
├── All unit tests passing ✅
└── Code coverage > 90%

Day 2: Integration Tests
├── Resolve E2B template access
├── Write 3-5 integration tests
├── Test with real E2B sandbox
├── Fix any issues
└── All integration tests passing ✅

Day 3: E2E Tests & Polish
├── Write 1-2 E2E tests
├── Test complete workflow
├── Add error handling, logging
├── Documentation
└── Ready for code review ✅
```

---

## 8. Test Metrics & Goals

| Metric | Target | Actual |
|--------|--------|--------|
| Code Coverage | > 90% | TBD |
| Unit Test Runtime | < 1s | TBD |
| Integration Test Runtime | < 60s | TBD |
| E2E Test Runtime | < 120s | TBD |
| All Tests Passing | 100% | TBD |

---

## 9. Example: Complete Test File

```python
# backend/tests/test_subfinder_agent.py
import pytest
from unittest.mock import Mock, patch
from src.agents.recon.subfinder_agent import SubfinderAgent, SubfinderError

class TestSubfinderAgent:
    """Complete test suite for SubfinderAgent."""

    @pytest.fixture
    def agent(self, tmp_path):
        workspace = Mock()
        agent = SubfinderAgent(workspace=workspace)
        agent.sandbox = Mock()
        return agent

    async def test_execute_success(self, agent):
        """Test successful execution."""
        agent.sandbox.commands.run.return_value = Mock(
            exit_code=0,
            stdout="sub1.example.com\nsub2.example.com\n",
            stderr=""
        )

        result = await agent.execute("example.com")

        assert len(result) == 2
        assert "sub1.example.com" in result

    async def test_execute_timeout(self, agent):
        """Test timeout handling."""
        agent.sandbox.commands.run.side_effect = TimeoutError()

        with pytest.raises(SubfinderError):
            await agent.execute("example.com", timeout=60)

    # ... 15-20 more unit tests ...

@pytest.mark.integration
class TestSubfinderIntegration:
    """Integration tests with real E2B."""

    async def test_real_execution(self):
        """Test with real E2B sandbox."""
        # Requires E2B_API_KEY
        pass

    # ... 5-8 integration tests ...
```

---

## Summary: Testing Strategy for Issue #13

✅ **Unit Tests** (15-20 tests, < 1s)
- Mock E2B sandbox
- Test all logic, edge cases, error handling
- Run on every commit

✅ **Integration Tests** (5-8 tests, < 60s)
- Real E2B sandbox + real Subfinder
- Test tool integration and workspace persistence
- Run on PR, requires `E2B_API_KEY`

✅ **E2E Tests** (1-2 tests, < 120s)
- Complete workflow from start to finish
- Run on main branch merges only

**Total Development Time**: 3 days
- Day 1: Implementation + unit tests
- Day 2: Integration tests + fix issues
- Day 3: E2E tests + polish + docs

**Next Step**: Resolve E2B template access, then start implementation! 🚀
