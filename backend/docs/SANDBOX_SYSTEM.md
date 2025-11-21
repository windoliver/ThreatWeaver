# Sandbox Execution System

**Issue:** #23 (Docker Sandboxing for Security Tools)
**Status:** Implemented (E2B Provider)
**Date:** 2025-11-20

---

## Overview

The Sandbox Execution System provides secure, isolated environments for running security tools (Nmap, Nuclei, Subfinder, HTTPx, SQLMap) with resource limits and automatic cleanup.

**Key Features:**
- ✅ E2B cloud sandbox provider (production-ready)
- ✅ Resource limits (CPU, memory, timeout)
- ✅ Filesystem isolation (read-only except /workspace)
- ✅ Automatic cleanup after execution
- ✅ File upload/download for workspace
- ✅ Comprehensive error handling
- ⏳ Docker provider (planned)

**Architecture Reference:** architecture.md - Infrastructure & Security Sandboxing

---

## Quick Start

### 1. Configuration

Set environment variables in `.env`:

```bash
# Sandbox Provider (e2b or docker)
E2B_API_KEY=e2b_your_api_key_here
SANDBOX_PROVIDER=e2b

# Resource Limits
SANDBOX_CPU_LIMIT=2.0        # CPU cores
SANDBOX_MEMORY_LIMIT=4096    # MB
SANDBOX_TIMEOUT=3600         # seconds (1 hour)
```

### 2. Basic Usage

```python
from src.sandbox import get_sandbox_provider, get_tool_config

# Get sandbox provider (E2B or Docker based on config)
provider = get_sandbox_provider()

# Configure tool execution
config = get_tool_config(
    "subfinder",
    domain="example.com",
    output_file="/workspace/subdomains.txt",
)

# Execute in sandbox
result = await provider.execute(
    tool_config=config,
    workspace_dir="/tmp/scan-123",
    scan_id="scan-123",
)

# Check results
if result.success:
    print(f"Subdomains found: {result.output_files['/workspace/subdomains.txt']}")
else:
    print(f"Error: {result.error}")
```

---

## Architecture

### Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     AGENT LAYER                             │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   │
│  │ Subfinder    │   │ HTTPx        │   │ Nmap         │   │
│  │ Agent        │   │ Agent        │   │ Agent        │   │
│  └──────────────┘   └──────────────┘   └──────────────┘   │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                   SANDBOX ABSTRACTION                        │
│                                                              │
│  ┌────────────────────────────────────────────────┐         │
│  │ SandboxProvider Protocol (Abstract Interface) │         │
│  └────────────────────────────────────────────────┘         │
│                          │                                   │
│         ┌────────────────┴────────────────┐                │
│         ▼                                  ▼                │
│  ┌──────────────┐                  ┌──────────────┐        │
│  │ E2B Provider │                  │ Docker       │        │
│  │ (Cloud)      │                  │ Provider     │        │
│  │ ✅ Ready     │                  │ ⏳ Planned   │        │
│  └──────────────┘                  └──────────────┘        │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                 EXECUTION ENVIRONMENT                        │
│                                                              │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   │
│  │ E2B Cloud    │   │ Docker       │   │ Nexus        │   │
│  │ Sandbox      │   │ Container    │   │ Workspace    │   │
│  │ (Isolated)   │   │ (Local)      │   │ (Storage)    │   │
│  └──────────────┘   └──────────────┘   └──────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Key Components

#### 1. **SandboxProvider (Protocol)**
Abstract interface defining sandbox operations:
```python
class SandboxProvider(ABC):
    @abstractmethod
    async def execute(
        self, tool_config: ToolConfig, workspace_dir: str, scan_id: str
    ) -> SandboxExecutionResult:
        """Execute a security tool in isolated sandbox."""

    @abstractmethod
    async def cleanup(self, scan_id: str) -> None:
        """Clean up sandbox resources."""

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if sandbox provider is healthy."""
```

#### 2. **E2BSandboxProvider**
Cloud-based sandbox using E2B:
- Secure isolated environments
- Automatic resource limits
- Network isolation
- File upload/download
- Automatic cleanup

#### 3. **ToolConfig**
Configuration for security tools:
```python
@dataclass
class ToolConfig:
    name: str                   # Tool name (e.g., "subfinder")
    image: str                  # Docker image or E2B template
    command: str                # Command to execute
    args: List[str]             # Command arguments
    env: Dict[str, str]         # Environment variables
    timeout: int = 3600         # Execution timeout (seconds)
    cpu_limit: float = 2.0      # CPU cores
    memory_limit: int = 4096    # Memory limit (MB)
    network_isolated: bool = True
```

#### 4. **SandboxExecutionResult**
Result of sandbox execution:
```python
@dataclass
class SandboxExecutionResult:
    success: bool               # Execution success
    exit_code: int              # Process exit code
    stdout: str                 # Standard output
    stderr: str                 # Standard error
    duration: float             # Execution duration (seconds)
    output_files: Dict[str, str]  # File paths → contents
    error: Optional[str]        # Error message if failed
```

---

## Security Features

### 1. **Resource Limits**
All tools run with enforced limits:
- **CPU**: 2 cores (configurable)
- **Memory**: 4GB (configurable)
- **Timeout**: 1 hour (configurable)
- **Network**: Isolated per scan

### 2. **Filesystem Isolation**
- Read-only filesystem except `/workspace`
- No access to host filesystem
- Workspace mounted per-scan
- Automatic cleanup after execution

### 3. **Network Isolation**
- Each scan gets isolated network
- No access to internal IPs (when enforced)
- Configurable network limits (10 Mbps default)

### 4. **Automatic Cleanup**
- Sandboxes destroyed after execution
- No resource leaks
- Workspace files preserved in Nexus

---

## Tool Configurations

### Subfinder (Subdomain Discovery)
```python
config = get_tool_config(
    "subfinder",
    domain="example.com",
    output_file="/workspace/subdomains.txt",
)

# Limits:
# - CPU: 1.0 cores
# - Memory: 1GB
# - Timeout: 30 minutes
```

### HTTPx (HTTP Probing)
```python
config = get_tool_config(
    "httpx",
    input_file="/workspace/subdomains.txt",
    output_file="/workspace/http.json",
)

# Limits:
# - CPU: 2.0 cores
# - Memory: 2GB
# - Timeout: 30 minutes
# - Output: JSON with tech detection
```

### Nmap (Port Scanning)
```python
config = get_tool_config(
    "nmap",
    target="10.0.0.1",
    output_file="/workspace/nmap.xml",
)

# Limits:
# - CPU: 2.0 cores
# - Memory: 2GB
# - Timeout: 1 hour
# - Scan type: -sV -sC (version + scripts)
```

### Nuclei (Vulnerability Scanning)
```python
config = get_tool_config(
    "nuclei",
    target_file="/workspace/targets.txt",
    output_file="/workspace/vulns.json",
)

# Limits:
# - CPU: 2.0 cores
# - Memory: 4GB (templates can be memory-intensive)
# - Timeout: 1 hour
# - Severity: critical, high, medium
```

### SQLMap (SQL Injection)
```python
config = get_tool_config(
    "sqlmap",
    target_url="https://example.com/api?id=1",
    output_dir="/workspace/sqlmap/",
)

# Limits:
# - CPU: 2.0 cores
# - Memory: 2GB
# - Timeout: 1 hour
# - Mode: Non-interactive (--batch)
# - Network: NOT isolated (needs target access)
```

---

## Error Handling

### Timeout Errors
```python
try:
    result = await provider.execute(config, workspace, scan_id)
except SandboxTimeoutError as e:
    logger.error(f"Tool exceeded timeout: {e}")
    # Mark scan as timed out
```

### Execution Errors
```python
try:
    result = await provider.execute(config, workspace, scan_id)
    if not result.success:
        logger.error(f"Tool failed: {result.stderr}")
        # Handle tool failure
except SandboxExecutionError as e:
    logger.error(f"Sandbox execution failed: {e}")
    # Handle sandbox infrastructure failure
```

### Resource Errors
```python
try:
    result = await provider.execute(config, workspace, scan_id)
except SandboxResourceError as e:
    logger.error(f"Resource limit exceeded: {e}")
    # Increase limits or optimize tool usage
```

---

## Testing

### Run Sandbox Tests
```bash
# Run all sandbox tests (requires E2B_API_KEY)
E2B_API_KEY=your_key pytest tests/test_sandbox.py -v

# Run configuration tests only (no E2B required)
pytest tests/test_sandbox.py::TestSandboxConfig -v

# Run E2B integration tests
E2B_API_KEY=your_key pytest tests/test_sandbox.py::TestE2BSandboxProvider -v
```

### Test Coverage
- ✅ Configuration loading from environment
- ✅ Tool config generators (5 tools)
- ✅ Sandbox provider factory
- ✅ E2B health check
- ✅ Simple command execution
- ✅ File creation and download
- ✅ Timeout enforcement
- ✅ Error handling
- ✅ Cleanup operations
- ✅ Multiple file outputs

---

## Production Deployment

### E2B Cloud (Recommended)

1. **Get E2B API Key:**
   ```bash
   # Sign up at https://e2b.dev
   # Get your API key from dashboard
   ```

2. **Set Environment Variables:**
   ```bash
   export E2B_API_KEY=e2b_your_api_key_here
   export SANDBOX_PROVIDER=e2b
   ```

3. **Verify Configuration:**
   ```python
   from src.sandbox import get_sandbox_provider

   provider = get_sandbox_provider()
   healthy = await provider.health_check()
   assert healthy, "Sandbox provider not healthy!"
   ```

### Docker (Local Development)

**Status:** Planned (not yet implemented)

When implemented, will support:
- Local Docker container execution
- Same interface as E2B provider
- Better for air-gapped environments
- Lower latency (no cloud calls)

---

## Known Issues

### SSL Certificate Issues (macOS/Anaconda)

**Problem:** `[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed`

**Solution:**
```bash
# Option 1: Install certifi
uv add certifi

# Option 2: Install macOS certificates (if using system Python)
/Applications/Python\ 3.12/Install\ Certificates.command

# Option 3: Use Anaconda SSL fix
conda install -c anaconda certifi
```

**Root Cause:** Python on macOS doesn't use system certificates by default. This affects E2B SDK's HTTPS calls.

---

## Integration with Agents

### LangGraph Integration
```python
from src.sandbox import get_sandbox_provider, get_tool_config
from src.agents.handoffs.schemas import ScanState

async def run_subfinder_agent(state: ScanState):
    """LangGraph node to run Subfinder agent."""
    provider = get_sandbox_provider()

    config = get_tool_config(
        "subfinder",
        domain=state["target"],
        output_file="/workspace/subdomains.txt",
    )

    result = await provider.execute(
        tool_config=config,
        workspace_dir=f"/tmp/{state['scan_id']}",
        scan_id=state["scan_id"],
    )

    if result.success:
        # Parse subdomain results
        subdomains = result.output_files["/workspace/subdomains.txt"].splitlines()

        # Update state with recon handoff
        state["recon_handoff"] = {
            "subdomains": subdomains,
            "metadata": {"duration": result.duration},
        }
    else:
        # Handle failure
        state["error"] = result.error

    return state
```

### Celery Task Integration
```python
from src.sandbox import get_sandbox_provider, get_tool_config
from celery import shared_task

@shared_task(bind=True, queue='recon')
def run_subfinder(self, domain: str, scan_id: str):
    """Celery task to run Subfinder in sandbox."""
    import asyncio

    provider = get_sandbox_provider()

    config = get_tool_config(
        "subfinder",
        domain=domain,
        output_file="/workspace/subdomains.txt",
    )

    result = asyncio.run(
        provider.execute(
            tool_config=config,
            workspace_dir=f"/tmp/{scan_id}",
            scan_id=scan_id,
        )
    )

    return {
        "success": result.success,
        "subdomains": result.output_files.get("/workspace/subdomains.txt", "").splitlines(),
        "duration": result.duration,
    }
```

---

## Future Enhancements

### Docker Provider (Issue #23 - Continued)
- [ ] Implement DockerSandboxProvider
- [ ] Create tool Docker images (Dockerfile for each tool)
- [ ] Resource limits via Docker (--cpus, --memory)
- [ ] Network isolation (bridge networks per scan)
- [ ] Read-only filesystem (--read-only flag)

### Enhanced Features
- [ ] Distributed tracing (OpenTelemetry)
- [ ] Cost optimization (sandbox pooling)
- [ ] Performance metrics (execution time, resource usage)
- [ ] Tool result caching (avoid duplicate scans)
- [ ] Parallel execution (multiple tools simultaneously)

---

## Files Created

**Core Infrastructure:**
- `src/sandbox/__init__.py` - Module exports
- `src/sandbox/protocol.py` - Abstract interface and data structures (142 lines)
- `src/sandbox/config.py` - Configuration and tool configs (240 lines)
- `src/sandbox/factory.py` - Provider factory function (57 lines)

**Providers:**
- `src/sandbox/providers/__init__.py` - Provider exports
- `src/sandbox/providers/e2b_provider.py` - E2B cloud implementation (324 lines)

**Tests:**
- `tests/test_sandbox.py` - Comprehensive test suite (430 lines)

**Configuration:**
- `.env.example` - Updated with sandbox settings
- `.env` - Local configuration with E2B key

**Documentation:**
- `docs/SANDBOX_SYSTEM.md` - This file (comprehensive guide)

**Total:** 1,193 lines of production code + tests + docs

---

## References

- **E2B Documentation:** https://e2b.dev/docs
- **Issue #23:** https://github.com/windoliver/ThreatWeaver/issues/23
- **Architecture:** architecture.md - Infrastructure & Security Sandboxing
- **Related Issues:**
  - #13: Subfinder Agent
  - #14: HTTPx Agent
  - #15: Nmap Agent
  - #17: Nuclei Agent
  - #18: SQLMap Agent

---

## Support

For issues or questions:
- GitHub Issues: https://github.com/windoliver/ThreatWeaver/issues
- E2B Support: https://e2b.dev/docs/getting-started/introduction
