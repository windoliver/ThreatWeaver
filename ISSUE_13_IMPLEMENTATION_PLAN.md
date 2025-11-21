# Issue #13: Subfinder Agent Implementation Plan

## Corrected Architecture: Using GCS via Nexus

You're absolutely right! We need to use **RemoteNexusFS with GCS connector**, not the simple `NexusFS("scan_12345")`.

### Correct Nexus Setup

```python
# ❌ WRONG (my mistake in testing plan)
workspace = NexusFS("scan_12345")

# ✅ CORRECT - Using GCS Connector
from nexus.backends.gcs_connector import GCSConnectorBackend
from nexus.core.nexus_fs import NexusFS

# Initialize GCS backend
backend = GCSConnectorBackend(
    bucket_name="threatweaver-scans",
    project_id="your-gcp-project",
    credentials_path="/path/to/credentials.json",  # or use ADC
    prefix="data"  # Optional: prefix all paths with "data/"
)

# Create NexusFS with GCS backend
nexus_fs = NexusFS(backend=backend)

# Now use it for agent workspace
# Files stored as: gs://threatweaver-scans/data/{team_id}/{scan_id}/
```

### Alternative: Remote Nexus Server

```python
# Connect to remote Nexus RPC server
from nexus.remote import RemoteNexusFS

nexus_fs = RemoteNexusFS(
    server_url="http://nexus-server:8080",
    api_key="your-api-key"
)
```

---

## Implementation Plan

### Phase 1: Configuration Setup (Day 1 Morning)

#### 1. Create Nexus Configuration Module

**File**: `backend/src/config/nexus_config.py`

```python
"""
Nexus filesystem configuration for ThreatWeaver.

Provides factory function to create NexusFS instances with appropriate backend
(GCS for production, local for development).
"""

import os
from pathlib import Path

from nexus.backends.gcs_connector import GCSConnectorBackend
from nexus.backends.local import LocalBackend
from nexus.core.nexus_fs import NexusFS


def get_nexus_fs() -> NexusFS:
    """
    Create NexusFS instance with appropriate backend based on environment.

    Returns:
        NexusFS instance configured for current environment

    Environment Variables:
        - NEXUS_BACKEND: "gcs" or "local" (default: "local")
        - GCS_BUCKET_NAME: GCS bucket name (required for GCS backend)
        - GCS_PROJECT_ID: GCP project ID (optional, inferred from credentials)
        - GCS_CREDENTIALS_PATH: Path to service account JSON (optional, uses ADC)
        - NEXUS_LOCAL_PATH: Local storage path (default: "./nexus-data")
        - NEXUS_DB_PATH: SQLite metadata DB path (default: "./nexus-metadata.db")

    Example (Local Development):
        >>> # .env
        >>> NEXUS_BACKEND=local
        >>> NEXUS_LOCAL_PATH=./nexus-data
        >>>
        >>> # Usage
        >>> nx = get_nexus_fs()
        >>> nx.write("/team-123/scan-456/results.json", b"...")

    Example (GCS Production):
        >>> # .env
        >>> NEXUS_BACKEND=gcs
        >>> GCS_BUCKET_NAME=threatweaver-scans
        >>> GCS_PROJECT_ID=threatweaver-prod
        >>> GCS_CREDENTIALS_PATH=/secrets/gcs-key.json
        >>>
        >>> # Usage
        >>> nx = get_nexus_fs()
        >>> # Files stored as: gs://threatweaver-scans/{team_id}/{scan_id}/...
    """
    backend_type = os.getenv("NEXUS_BACKEND", "local").lower()

    if backend_type == "gcs":
        # GCS Backend (Production)
        bucket_name = os.getenv("GCS_BUCKET_NAME")
        if not bucket_name:
            raise ValueError("GCS_BUCKET_NAME environment variable required for GCS backend")

        project_id = os.getenv("GCS_PROJECT_ID")
        credentials_path = os.getenv("GCS_CREDENTIALS_PATH")

        backend = GCSConnectorBackend(
            bucket_name=bucket_name,
            project_id=project_id,
            credentials_path=credentials_path,
            prefix="",  # No prefix, use full paths like /{team_id}/{scan_id}/
        )

    else:
        # Local Backend (Development)
        local_path = os.getenv("NEXUS_LOCAL_PATH", "./nexus-data")
        Path(local_path).mkdir(parents=True, exist_ok=True)

        backend = LocalBackend(storage_path=local_path)

    # Create NexusFS with backend
    db_path = os.getenv("NEXUS_DB_PATH", "./nexus-metadata.db")

    nexus_fs = NexusFS(
        backend=backend,
        db_path=db_path,
        enable_metadata_cache=True,
        enable_content_cache=True,
        auto_parse=False,  # Don't auto-parse security tool outputs
    )

    return nexus_fs
```

#### 2. Update `.env.example`

```bash
# Add to backend/.env.example

# Nexus Configuration
NEXUS_BACKEND=local  # Options: local, gcs
NEXUS_LOCAL_PATH=./nexus-data
NEXUS_DB_PATH=./nexus-metadata.db

# GCS Configuration (for production)
GCS_BUCKET_NAME=threatweaver-scans
GCS_PROJECT_ID=your-gcp-project-id
GCS_CREDENTIALS_PATH=/path/to/gcs-key.json
```

---

### Phase 2: Subfinder Agent Implementation (Day 1 Afternoon)

#### 3. Create Subfinder Agent

**File**: `backend/src/agents/recon/subfinder_agent.py`

```python
"""
Subfinder Agent - Subdomain Discovery.

Uses Subfinder tool in E2B sandbox to discover subdomains for target domains.
Results are stored in Nexus workspace for downstream agents.

Reference:
- Issue #13: Implement Subfinder Agent
- E2B Template ID: dbe6pq4es6hqj31ybd38 (threatweaver-security)
"""

import json
import logging
from datetime import datetime
from typing import List, Optional

from src.agents.backends.nexus_backend import NexusBackend
from src.sandbox.factory import SandboxFactory
from src.sandbox.protocol import SandboxProtocol

logger = logging.getLogger(__name__)


class SubfinderError(Exception):
    """Exceptions raised by Subfinder agent."""
    pass


class SubfinderAgent:
    """
    Subdomain discovery agent using Subfinder in E2B sandbox.

    This agent:
    1. Runs Subfinder in E2B sandbox (isolated, secure execution)
    2. Parses subdomain results
    3. Filters wildcards and duplicates
    4. Stores results in Nexus workspace

    Storage:
        /{team_id}/{scan_id}/recon/subfinder/subdomains.json
        /{team_id}/{scan_id}/recon/subfinder/raw_output.txt

    Example:
        >>> from config.nexus_config import get_nexus_fs
        >>> agent = SubfinderAgent(
        ...     scan_id="scan-123",
        ...     team_id="team-abc",
        ...     nexus_fs=get_nexus_fs()
        ... )
        >>> subdomains = await agent.execute("example.com")
        >>> print(f"Found {len(subdomains)} subdomains")
    """

    def __init__(
        self,
        scan_id: str,
        team_id: str,
        nexus_backend: NexusBackend,
        sandbox: Optional[SandboxProtocol] = None,
    ):
        """
        Initialize Subfinder agent.

        Args:
            scan_id: Scan identifier
            team_id: Team identifier (for multi-tenancy)
            nexus_backend: NexusBackend for workspace file operations
            sandbox: E2B sandbox instance (auto-created if None)
        """
        self.scan_id = scan_id
        self.team_id = team_id
        self.backend = nexus_backend

        # Initialize E2B sandbox with security tools template
        self.sandbox = sandbox or SandboxFactory.create(
            provider="e2b",
            template_id="dbe6pq4es6hqj31ybd38"  # threatweaver-security
        )

    async def execute(
        self,
        domain: str,
        timeout: int = 300,
        filter_wildcards: bool = True,
    ) -> List[str]:
        """
        Discover subdomains for target domain.

        Args:
            domain: Target domain (e.g., "example.com")
            timeout: Execution timeout in seconds (default: 5 minutes)
            filter_wildcards: Remove wildcard DNS entries (default: True)

        Returns:
            List of discovered subdomains

        Raises:
            SubfinderError: If execution fails or times out

        Example:
            >>> subdomains = await agent.execute("hackerone.com")
            >>> print(subdomains)
            ['www.hackerone.com', 'api.hackerone.com', 'docs.hackerone.com']
        """
        logger.info(f"Starting subdomain discovery for {domain}")

        try:
            # Validate domain
            self._validate_domain(domain)

            # Run Subfinder in E2B sandbox
            result = await self._run_subfinder(domain, timeout)

            # Parse and clean results
            subdomains = self._parse_output(result.stdout, filter_wildcards)

            # Store results in Nexus workspace
            await self._store_results(domain, subdomains, result.stdout)

            logger.info(f"Found {len(subdomains)} subdomains for {domain}")
            return subdomains

        except Exception as e:
            logger.error(f"Subfinder execution failed for {domain}: {e}")
            raise SubfinderError(f"Subdomain discovery failed: {e}") from e

    async def _run_subfinder(self, domain: str, timeout: int):
        """Execute Subfinder in E2B sandbox."""
        command = f"subfinder -d {domain} -silent"

        try:
            result = await self.sandbox.run_command(command, timeout=timeout)

            if result.exit_code != 0:
                raise SubfinderError(
                    f"Subfinder returned exit code {result.exit_code}: {result.stderr}"
                )

            return result

        except TimeoutError:
            raise SubfinderError(f"Subfinder timed out after {timeout}s")

    def _validate_domain(self, domain: str) -> None:
        """Validate domain format."""
        import re

        # Simple domain validation
        pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"

        if not re.match(pattern, domain):
            raise ValueError(f"Invalid domain format: {domain}")

    def _parse_output(
        self,
        stdout: str,
        filter_wildcards: bool = True
    ) -> List[str]:
        """Parse Subfinder output and clean results."""
        # Remove ANSI color codes
        ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
        clean_output = ansi_escape.sub('', stdout)

        # Split into lines and filter
        subdomains = []
        for line in clean_output.strip().split('\n'):
            subdomain = line.strip()

            if not subdomain:
                continue

            # Filter wildcards
            if filter_wildcards and subdomain.startswith('*'):
                continue

            subdomains.append(subdomain)

        # Remove duplicates while preserving order
        seen = set()
        unique_subdomains = []
        for sub in subdomains:
            if sub not in seen:
                seen.add(sub)
                unique_subdomains.append(sub)

        return unique_subdomains

    async def _store_results(
        self,
        domain: str,
        subdomains: List[str],
        raw_output: str
    ) -> None:
        """Store results in Nexus workspace."""
        timestamp = datetime.utcnow().isoformat()

        # Store structured JSON results
        results_data = {
            "domain": domain,
            "subdomains": subdomains,
            "count": len(subdomains),
            "timestamp": timestamp,
            "scan_id": self.scan_id,
            "team_id": self.team_id,
            "tool": "subfinder",
            "version": "2.6.3"
        }

        results_json = json.dumps(results_data, indent=2)
        self.backend.write(
            "/recon/subfinder/subdomains.json",
            results_json
        )

        # Store raw output for debugging
        self.backend.write(
            "/recon/subfinder/raw_output.txt",
            raw_output
        )

        logger.info(f"Stored results in Nexus workspace: {self.scan_id}")

    def cleanup(self) -> None:
        """Cleanup sandbox resources."""
        if self.sandbox:
            self.sandbox.kill()
```

---

### Phase 3: Testing (Day 2)

#### 4. Unit Tests

**File**: `backend/tests/test_subfinder_agent.py`

```python
import pytest
from unittest.mock import Mock, AsyncMock, patch

from src.agents.recon.subfinder_agent import SubfinderAgent, SubfinderError


@pytest.fixture
def mock_sandbox():
    """Mock E2B sandbox."""
    sandbox = Mock()
    sandbox.run_command = AsyncMock()
    return sandbox


@pytest.fixture
def mock_backend():
    """Mock Nexus backend."""
    backend = Mock()
    backend.write = Mock(return_value=Mock(error=None))
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


class TestSubfinderAgent:
    """Unit tests for SubfinderAgent."""

    @pytest.mark.asyncio
    async def test_execute_success(self, agent, mock_sandbox):
        """Test successful subdomain discovery."""
        # Arrange
        mock_result = Mock(
            exit_code=0,
            stdout="sub1.example.com\nsub2.example.com\nsub3.example.com\n",
            stderr=""
        )
        mock_sandbox.run_command.return_value = mock_result

        # Act
        subdomains = await agent.execute("example.com")

        # Assert
        assert len(subdomains) == 3
        assert "sub1.example.com" in subdomains
        mock_sandbox.run_command.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_no_results(self, agent, mock_sandbox):
        """Test when no subdomains found."""
        mock_result = Mock(exit_code=0, stdout="", stderr="")
        mock_sandbox.run_command.return_value = mock_result

        subdomains = await agent.execute("nonexistent.com")

        assert len(subdomains) == 0

    @pytest.mark.asyncio
    async def test_execute_with_wildcards(self, agent, mock_sandbox):
        """Test wildcard filtering."""
        mock_result = Mock(
            exit_code=0,
            stdout="*.cdn.example.com\nsub1.example.com\n*.wildcard.example.com\n",
            stderr=""
        )
        mock_sandbox.run_command.return_value = mock_result

        subdomains = await agent.execute("example.com", filter_wildcards=True)

        assert len(subdomains) == 1
        assert "sub1.example.com" in subdomains

    @pytest.mark.asyncio
    async def test_execute_invalid_domain(self, agent):
        """Test invalid domain validation."""
        with pytest.raises(ValueError, match="Invalid domain"):
            await agent.execute("not a domain!")

    @pytest.mark.asyncio
    async def test_execute_timeout(self, agent, mock_sandbox):
        """Test timeout handling."""
        mock_sandbox.run_command.side_effect = TimeoutError()

        with pytest.raises(SubfinderError, match="timed out"):
            await agent.execute("example.com", timeout=60)
```

---

### Phase 4: Integration Testing (Day 2)

#### 5. Integration Test with Real E2B

**File**: `backend/tests/integration/test_subfinder_integration.py`

```python
import pytest
import os

from src.agents.recon.subfinder_agent import SubfinderAgent
from src.agents.backends.nexus_backend import NexusBackend
from src.config.nexus_config import get_nexus_fs
from src.sandbox.factory import SandboxFactory


@pytest.mark.integration
@pytest.mark.skipif(
    not os.getenv("E2B_API_KEY"),
    reason="E2B_API_KEY not set"
)
class TestSubfinderIntegration:
    """Integration tests with real E2B sandbox."""

    @pytest.mark.asyncio
    async def test_real_subfinder_execution(self, tmp_path):
        """Test with real E2B sandbox and Subfinder."""
        # Create test workspace
        nexus_fs = get_nexus_fs()
        backend = NexusBackend("test-scan", "test-team", nexus_fs)

        # Create real E2B sandbox
        sandbox = SandboxFactory.create("e2b", template_id="dbe6pq4es6hqj31ybd38")

        try:
            # Create agent
            agent = SubfinderAgent(
                scan_id="test-scan",
                team_id="test-team",
                nexus_backend=backend,
                sandbox=sandbox
            )

            # Execute
            subdomains = await agent.execute("google.com")

            # Verify
            assert len(subdomains) > 0
            assert any("google.com" in sub for sub in subdomains)

            # Verify workspace storage
            files = backend.get_all_files()
            assert "recon/subfinder/subdomains.json" in files

        finally:
            # Cleanup
            sandbox.kill()
```

---

## Implementation Checklist

### Day 1
- [ ] Create `backend/src/config/__init__.py`
- [ ] Create `backend/src/config/nexus_config.py` with GCS setup
- [ ] Update `backend/.env.example` with Nexus config
- [ ] Create `backend/src/agents/recon/__init__.py`
- [ ] Implement `backend/src/agents/recon/subfinder_agent.py`
- [ ] Write unit tests in `backend/tests/test_subfinder_agent.py`
- [ ] All unit tests passing (15-20 tests)

### Day 2
- [ ] Resolve E2B template access (make public or update key)
- [ ] Write integration tests
- [ ] Test with real E2B sandbox
- [ ] Test GCS storage (if GCS configured)
- [ ] Verify Nexus workspace structure
- [ ] All tests passing (unit + integration)

### Day 3
- [ ] Add error handling and logging
- [ ] Add docstrings and type hints
- [ ] Create documentation
- [ ] Code review and refactor
- [ ] Ready for Issue #14 (HTTPx Agent)

---

## Key Differences from My Earlier Mistake

| ❌ Wrong (My Mistake) | ✅ Correct (Your Fix) |
|----------------------|----------------------|
| `workspace = NexusFS("scan_123")` | `backend = GCSConnectorBackend(bucket="..."); nx = NexusFS(backend=backend)` |
| No backend specified | Explicit GCS or Local backend |
| Direct NexusFS instantiation | Factory function `get_nexus_fs()` |
| Hardcoded local storage | Environment-based backend selection |

---

## Next Steps

1. **Create config module first** (30 minutes)
2. **Implement Subfinder agent** (2-3 hours)
3. **Write unit tests** (2-3 hours)
4. **Test with real E2B** (1 hour)
5. **Polish and document** (1 hour)

**Ready to start?** Let's begin with creating the Nexus configuration module! 🚀
