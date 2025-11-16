# ThreatWeaver Technical Architecture

**Version**: 1.1
**Last Updated**: 2025-11-16
**Status**: Architecture Design Document

---

## 📋 Version History

### Version 1.2 (2025-11-16)

**Major Additions**:

1. **Next.js SaaS Starter Integration** ⭐
   - Complete frontend architecture based on [Next.js SaaS Starter](https://github.com/nextjs/saas-starter)
   - Production-ready auth (NextAuth.js), payments (Stripe), teams
   - Multi-tenant architecture with row-level security
   - Pricing tiers: Free, Pro ($99/mo), Enterprise ($499/mo)
   - Project structure, deployment guide (Vercel), backend integration

2. **Security Tool Sandboxing** 🔒 (CRITICAL)
   - **MVP**: Docker containers with resource limits (CPU, memory, network)
   - **Phase 2**: Firecracker microVMs for stronger isolation
   - Network isolation strategy (dedicated VPC, rotating proxies)
   - Scope validation (DNS TXT verification, blocklists)
   - Per-scan resource limits and per-team quotas

3. **CAI-Inspired Enhancements** 🎯 (NEW)
   - **Multi-model flexibility**: LiteLLM integration (300+ models, 27% cost savings)
   - **Prompt injection guardrails**: Multi-layered defense (input sanitization, structured outputs)
   - **Agent handoffs**: Structured TypedDict schemas for context preservation
   - **HITL approval workflow**: Database-backed approval system with real-time notifications
   - See [LEARNINGS_FROM_CAI.md](./LEARNINGS_FROM_CAI.md) for detailed implementation

4. **Hybrid Handoff Architecture** 🔄 (NEW)
   - **LangGraph state**: In-memory handoffs during active scan (fast, ephemeral)
   - **Nexus workspace**: Persistent handoffs for historical context (versioned, searchable)
   - Best of both worlds: 3% faster workflows + cross-scan knowledge
   - See [NEXUS_VS_HANDOFFS.md](./NEXUS_VS_HANDOFFS.md) for architecture decision

**Key Refinements**:

5. **Task Processing Layer Clarification**:
   - Clear separation: Celery = raw job runner, LangGraph = reasoning brain
   - Celery handles fire-and-forget tool execution (Nmap, Nuclei, etc.)
   - LangGraph decides "what next?" based on results, enqueues jobs via Celery
   - No overlap in responsibilities

6. **Storage Strategy (MVP-First)**:
   - **MVP**: PostgreSQL + S3 (simple, proven, cost-effective)
   - **Phase 2**: Add Elasticsearch when search/analytics demands increase
   - Nexus VFS: Workspace abstraction over S3 (versioned scan directories)
   - **Handoff strategy**: In-memory (LangGraph) during scan, persist to Nexus at end

7. **Future Tool Additions**:
   - **Amass**: Deep enumeration for high-value targets (Phase 2)
   - **OSINT tools**: theHarvester, SpiderFoot for ReconEngine (Phase 2)
   - Detailed integration patterns and workflow examples
   - See "Future Evolution" section for phased roadmap

**Philosophy**: Start lean (Postgres + S3 + Docker), learn from proven frameworks (CAI), add complexity only when proven necessary by real usage data.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [System Design Principles](#system-design-principles)
3. [Core Architecture Layers](#core-architecture-layers)
4. [Multi-Agent System Design](#multi-agent-system-design)
5. [Security Tool Integration](#security-tool-integration)
6. [Workflow Orchestration Patterns](#workflow-orchestration-patterns)
7. [Technology Stack](#technology-stack)
8. [Scalability & Performance](#scalability--performance)
9. [Security & Compliance](#security--compliance)
10. [Deployment Architecture](#deployment-architecture)
11. [Future Evolution](#future-evolution)
12. [Comparison with Similar Tools](#comparison-with-similar-tools)

---

## Architecture Overview

ThreatWeaver is a **cloud-native, multi-agent cybersecurity platform** that provides comprehensive offensive security automation through intelligent orchestration of industry-standard security tools. The platform leverages hierarchical agent coordination (LangGraph DeepAgents) and shared workspace patterns (Nexus) to deliver adaptive, end-to-end security assessments.

### Core Capabilities

- **Two-Engine Architecture** (Inspired by Syntar & DeepAgents):
  - **ReconEngine**: Automated attack surface discovery and mapping (subdomains, networks, services)
  - **AssessmentEngine**: Intelligent vulnerability scanning and exploitation with LLM-powered decision-making
- **13+ Specialized Agents**: Coordinated workflow from reconnaissance to exploitation
- **Intelligent Orchestration**: Adaptive planning based on findings, dynamic task decomposition
- **Industry-Standard Tools**: Nmap, Nuclei, Subfinder, HTTPx, SQLMap, and extensible plugin architecture
- **Shared Workspace**: Versioned, persistent state across agents with complete audit trail
- **Continuous Monitoring**: Event-driven workflows for ongoing attack surface tracking
- **Human-in-Loop**: Approval workflows for critical operations (exploitation, data extraction)

### High-Level Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                     User Interface Layer                         │
│  ┌────────────────────┐              ┌──────────────────────┐    │
│  │  Web Dashboard     │              │   CLI Interface      │    │
│  │  (Next.js)         │              │   (Python REPL)      │    │
│  └────────────────────┘              └──────────────────────┘    │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │              REST/GraphQL API (FastAPI)                  │    │
│  └──────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
                            ▼                    ▼
┌──────────────────────────────────────────────────────────────────┐
│                  Application Services Layer                       │
│  ┌───────────────┐  ┌──────────────┐  ┌─────────────────────┐   │
│  │   Scan        │  │   Alert &    │  │   User & Auth       │   │
│  │   Manager     │  │   Webhook    │  │   Service           │   │
│  └───────────────┘  └──────────────┘  └─────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
                            ▼                    ▼
┌──────────────────────────────────────────────────────────────────┐
│            Two-Engine Multi-Agent Architecture                    │
│  ┌─────────────────────────────────────────────────────────┐     │
│  │  ReconEngine (Tier 1: Attack Surface Discovery)        │     │
│  │  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐    │     │
│  │  │  Subdomain  │  │   Network   │  │     HTTP     │    │     │
│  │  │  Discovery  │  │   Mapping   │  │   Probing    │    │     │
│  │  │ (Subfinder) │  │   (Nmap)    │  │   (HTTPx)    │    │     │
│  │  └─────────────┘  └─────────────┘  └──────────────┘    │     │
│  │  ┌──────────────────────────────────────────────────┐   │     │
│  │  │    Recon Coordinator (LangGraph)                 │   │     │
│  │  └──────────────────────────────────────────────────┘   │     │
│  └─────────────────────────────────────────────────────────┘     │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────┐     │
│  │  AssessmentEngine (Tier 2: Security Testing)           │     │
│  │  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐    │     │
│  │  │Vulnerability│  │     SQL     │  │   Exploit    │    │     │
│  │  │  Scanner    │  │  Injection  │  │ Coordinator  │    │     │
│  │  │  (Nuclei)   │  │  (SQLMap)   │  │ (LLM-based)  │    │     │
│  │  └─────────────┘  └─────────────┘  └──────────────┘    │     │
│  │  ┌──────────────────────────────────────────────────┐   │     │
│  │  │  Assessment Supervisor (Adaptive Planning)       │   │     │
│  │  └──────────────────────────────────────────────────┘   │     │
│  └─────────────────────────────────────────────────────────┘     │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────┐     │
│  │  Intelligence Layer (Cross-Engine)                      │     │
│  │  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐    │     │
│  │  │  Knowledge  │  │   Report    │  │    Alert     │    │     │
│  │  │  Manager    │  │  Generator  │  │   Monitor    │    │     │
│  │  │  (Nexus)    │  │ (LLM-based) │  │ (Rules/ML)   │    │     │
│  │  └─────────────┘  └─────────────┘  └──────────────┘    │     │
│  └─────────────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────────┘
                            ▼                    ▼
┌──────────────────────────────────────────────────────────────────┐
│                    Task Processing Layer                          │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │   Celery + Redis (Job Runner)                            │    │
│  │  ┌──────────────┐  ┌───────────────┐  ┌──────────────┐  │    │
│  │  │ Tool Exec    │  │   Long Jobs   │  │ Report Gen   │  │    │
│  │  │ (Nmap, etc)  │  │   (SQLMap)    │  │ (PDF/JSON)   │  │    │
│  │  └──────────────┘  └───────────────┘  └──────────────┘  │    │
│  └──────────────────────────────────────────────────────────┘    │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │   LangGraph Orchestration (Reasoning Brain)              │    │
│  │  - Adaptive planning: "What should we do next?"          │    │
│  │  - Result analysis: Parse outputs, make decisions        │    │
│  │  - Job delegation: Enqueue Celery tasks based on plan    │    │
│  └──────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
                            ▼                    ▼
┌──────────────────────────────────────────────────────────────────┐
│                      Storage & State Layer                        │
│  ┌─────────────────────────────────────────────────────────┐     │
│  │                    MVP Storage (v1)                     │     │
│  │  ┌──────────────┐              ┌─────────────────────┐  │     │
│  │  │ PostgreSQL   │              │   S3 / MinIO        │  │     │
│  │  │ • Scans meta │              │   • Nmap XML        │  │     │
│  │  │ • Users/auth │              │   • Nuclei JSON     │  │     │
│  │  │ • Configs    │              │   • Reports/logs    │  │     │
│  │  │ • Findings*  │              │   • Evidence/PoCs   │  │     │
│  │  └──────────────┘              └─────────────────────┘  │     │
│  │  * Relational queries, dashboards, recent scans         │     │
│  └─────────────────────────────────────────────────────────┘     │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────┐     │
│  │              Nexus VFS (Workspace Layer)                │     │
│  │  • Abstraction over S3 (versioned scan directories)     │     │
│  │  • Agent scratch space: /workspace/{scan_id}/...        │     │
│  │  • Enables time-travel, diffs, audit trail              │     │
│  └─────────────────────────────────────────────────────────┘     │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────┐     │
│  │          Phase 2: Add Elasticsearch (Optional)          │     │
│  │  • Add when: 1000+ scans/month, complex analytics       │     │
│  │  • Use for: Full-text search, aggregations, dashboards  │     │
│  └─────────────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────────┘
```

---

## System Design Principles

### 1. Hierarchical Multi-Agent Coordination (DeepAgents Pattern)

**Supervisor-Subordinate Model**:
- **Supervisor Agents** handle strategic planning, task decomposition, and result aggregation
- **Specialized Agents** execute specific security tools with focused contexts
- **Isolation**: SubAgentMiddleware prevents context pollution between agents
- **Adaptive Planning**: TodoListMiddleware enables dynamic task adjustment based on findings

**Benefits**:
- Clear separation of concerns (planning vs execution)
- Scalable agent architecture (add new tools without changing orchestration)
- Context-efficient (focused contexts reduce LLM token usage)
- Debugging-friendly (isolated execution traces)

### 2. Dual-Layer Task Processing (Celery + LangGraph)

**Critical Distinction**: Two orchestration layers with clear separation of concerns.

**Layer 1: Celery (Job Runner) - "The Executor"**:
- **Responsibility**: Fire-and-forget job execution for long-running tools
- **Use Cases**:
  - Run Nmap scans (30s - 5min)
  - Execute Nuclei templates (1-10min)
  - SQLMap injection tests (5min - 1hr)
  - Generate PDF reports (10-30s)
- **Pattern**: Worker pools consume tasks from Redis queue
- **No Intelligence**: Just executes, retries on failure, logs completion

**Layer 2: LangGraph (Reasoning Brain) - "The Strategist"**:
- **Responsibility**: Adaptive planning, result analysis, and strategic decisions
- **Use Cases**:
  - Parse Nmap results: "What services are high-value?"
  - Prioritize vulnerabilities: "Which finding should we exploit first?"
  - Decide next steps: "Should we run deep OSINT on this target?"
  - Generate human-readable summaries
- **Pattern**: Graph execution with LLM-powered decision nodes
- **Intelligence**: Context-aware, learns from findings, requests human approval

**How They Work Together**:
```python
# LangGraph supervisor decides what to do
supervisor_plan = """
☐ Run subdomain enumeration
☐ Analyze results and prioritize targets
☐ Scan high-value targets with Nuclei
"""

# Step 1: LangGraph enqueues Celery job
celery_task = run_subfinder.delay(domain="target.com")

# Step 2: Celery worker executes Subfinder
# (writes results to /workspace/{scan_id}/recon/subfinder/)

# Step 3: LangGraph retrieves results from workspace
subdomains = read_workspace(f"{scan_id}/recon/subfinder/results.json")

# Step 4: LangGraph analyzes with LLM
high_value_targets = llm.analyze(
    "Which of these subdomains are high-value targets?",
    context=subdomains
)

# Step 5: LangGraph enqueues next Celery job
celery_task = run_nuclei.delay(targets=high_value_targets)
```

**Why This Separation Matters**:
- **Celery doesn't reason**: It just runs tools reliably
- **LangGraph doesn't execute**: It delegates to Celery, focuses on "what next?"
- **No overlap**: Each layer does one thing well
- **Scalable**: Add Celery workers for throughput, LLM for intelligence

**Anti-Pattern to Avoid**:
- ❌ Don't let LangGraph also handle job scheduling (use Celery for that)
- ❌ Don't put decision logic in Celery workers (that's LangGraph's job)
- ✅ Keep concerns separated: Execution vs Reasoning

### 3. MVP-First Storage Strategy

**Philosophy**: Start simple, add complexity only when proven necessary.

**MVP Storage (PostgreSQL + S3)**:
```yaml
PostgreSQL (Relational):
  Use For:
    - Scan metadata (scan_id, user, timestamp, status)
    - User accounts and authentication
    - Agent configurations and rules
    - Recent findings (last 90 days) for fast queries
    - Dashboard data (counts, aggregations)

  Why PostgreSQL:
    - JSONB for flexible finding schema
    - Full-text search (good enough for MVP)
    - Proven reliability, simple backup/restore
    - Great for relational queries (user → scans → findings)

S3 / MinIO (Object Storage):
  Use For:
    - Raw tool outputs (Nmap XML, Nuclei JSON)
    - Large artifacts (screenshots, pcaps, logs)
    - Generated reports (PDF, HTML, Markdown)
    - Evidence archives (exploit PoCs, extracted data)
    - Historical scan data (> 90 days)

  Why S3:
    - Unlimited storage, cheap ($0.023/GB/month)
    - Versioning and lifecycle policies (auto-archive)
    - Nexus VFS abstraction layer on top
    - Easy integration with report generation

Nexus VFS Layer:
  What It Does:
    - Abstraction over S3 (versioned scan directories)
    - Agent scratch space: /workspace/{scan_id}/...
    - Enables time-travel, diffs, audit trail
    - Transparent to agents (they just read/write files)

  Implementation:
    - Backed by S3 buckets with versioning enabled
    - PostgreSQL stores metadata (file paths, versions, access logs)
    - Python SDK: nx.workspace.read(), nx.workspace.write()
```

**When to Add Elasticsearch (Phase 2)**:
```yaml
Triggers:
  - ✅ 1000+ scans per month (search becomes bottleneck)
  - ✅ Complex analytics needed (aggregations, trends)
  - ✅ Full-text search across all findings (not just recent)
  - ✅ Real-time dashboards with sub-second queries

Benefits:
  - Lightning-fast search across millions of findings
  - Advanced aggregations (CVE trends, attack surface growth)
  - Kibana dashboards for executives

Cost:
  - +$300-500/month for managed ES cluster
  - Operational complexity (index management, backups)

Decision: Defer until proven necessary by usage metrics
```

**Anti-Pattern to Avoid**:
- ❌ Don't add Elasticsearch "just in case" (premature optimization)
- ❌ Don't duplicate data (Postgres AND ES for same data)
- ✅ Start with Postgres + S3, measure performance, add ES when needed

### 4. Hybrid Agent Handoff Architecture (CAI-Inspired) 🔄

**The Challenge**: Balance speed (in-memory) with persistence (historical context)

**Solution**: Use **both** LangGraph state and Nexus workspace strategically

**Layer 1: In-Memory Handoffs (LangGraph State)**
```python
from typing import TypedDict, List, Optional

class ReconHandoff(TypedDict):
    """Ephemeral handoff data (in-memory during active scan)"""
    subdomains: List[str]
    live_hosts: List[dict]
    high_value_targets: List[str]  # LLM-prioritized
    metadata: dict

class AssessmentHandoff(TypedDict):
    """Ephemeral handoff data (in-memory during active scan)"""
    vulnerabilities: List[dict]
    critical_findings: List[str]
    suggested_exploits: List[str]
    metadata: dict

class ScanState(TypedDict):
    """LangGraph workflow state (in-memory, fast)"""
    scan_id: str
    team_id: str
    target: str

    # Active scan handoffs (ephemeral, in-memory only)
    recon_handoff: Optional[ReconHandoff]
    assessment_handoff: Optional[AssessmentHandoff]

    # Historical context (loaded from Nexus)
    previous_recon: Optional[ReconHandoff]
    previous_assessment: Optional[AssessmentHandoff]

    # Diff analysis
    new_subdomains: List[str]
    fixed_vulnerabilities: List[str]

# Fast in-memory handoff analysis
def recon_to_assessment_handoff(state: ScanState) -> ScanState:
    """
    Handoff: Recon → Assessment
    - Analyze current results (in-memory, fast)
    - Compare with previous scan (from Nexus)
    - Prioritize targets based on diff
    """
    # Load historical context from Nexus
    state['previous_recon'] = load_previous_recon(state['team_id'], state['target'])

    # LLM analyzes with history
    if state['previous_recon']:
        diff = llm.analyze(
            f"Current: {len(state['recon_handoff']['subdomains'])} subdomains, "
            f"Previous: {len(state['previous_recon']['subdomains'])} subdomains"
        )
        state['new_subdomains'] = diff['new']  # In-memory handoff
        state['next_step'] = 'deep_osint' if diff['recommend_amass'] else 'vuln_scan'

    return state  # In-memory, no disk I/O
```

**Layer 2: Persistent Handoffs (Nexus Workspace)**
```python
import nexus as nx

class HandoffPersistence:
    """Persist ephemeral handoffs to Nexus for cross-scan knowledge"""

    @staticmethod
    def save_recon_handoff(scan_id: str, team_id: str, handoff: ReconHandoff):
        """Write handoff to Nexus after scan completes (once)"""
        workspace = nx.workspace(f"/workspace/{team_id}/{scan_id}")
        workspace.write("recon/handoff.json", {
            **handoff,
            "timestamp": datetime.utcnow().isoformat()
        })

    @staticmethod
    def load_previous_recon(team_id: str, target: str) -> Optional[ReconHandoff]:
        """Load handoff from previous scan for historical context"""
        # Query Nexus memory for last scan
        previous = nx.memory.query(
            scope=f"scans/{team_id}",
            filter=f"target == '{target}'",
            order_by="timestamp DESC",
            limit=1
        )
        if not previous:
            return None  # First scan

        # Load persisted handoff
        workspace = nx.workspace(f"/workspace/{team_id}/{previous[0]['scan_id']}")
        return workspace.read("recon/handoff.json")

# At end of scan, persist for next scan
def finalize_scan(state: ScanState):
    HandoffPersistence.save_recon_handoff(
        scan_id=state['scan_id'],
        team_id=state['team_id'],
        handoff=state['recon_handoff']  # Write once at end
    )
```

**Benefits**:
- ✅ **Fast**: In-memory handoffs during active scan (no S3 latency, 3% faster)
- ✅ **Persistent**: Historical context from previous scans (versioned, searchable)
- ✅ **Type-safe**: TypedDict schemas enforce handoff contracts
- ✅ **Diff detection**: "50 new subdomains since last scan"
- ✅ **Adaptive workflows**: LLM decides to run Amass based on changes

**Use Cases**:
- Active scan: SubdomainAgent → (in-memory handoff) → HTTPxAgent
- Cross-scan: "Which subdomains are NEW?" (Nexus comparison)
- Trend analysis: "Attack surface growth over 6 months" (Nexus memory)

**See**: [NEXUS_VS_HANDOFFS.md](./NEXUS_VS_HANDOFFS.md) for detailed architecture decision

### 5. Multi-Model Flexibility (LiteLLM) 🎯

**Challenge**: Hard-coded to 3 LLM providers limits cost optimization and vendor independence

**Solution**: LiteLLM abstraction (supports 300+ models)

```python
from litellm import completion

# Per-agent model selection (cost optimization)
recon_supervisor = Agent(model="gpt-4o-mini")  # Fast, cheap ($0.08/scan)
exploit_supervisor = Agent(model="claude-3-opus")  # Deep reasoning ($0.45/scan)
report_generator = Agent(model="ollama/llama3")  # Free, local (air-gapped)

# Per-team model configuration (database)
team_settings = {
    "recon_model": "gpt-4o-mini",
    "assessment_model": "claude-3-opus",
    "budget_cap": 500  # USD per month
}

# Automatic fallback if budget exceeded
if team_llm_spend > team_settings['budget_cap']:
    model = team_settings['fallback_model']  # ollama/llama3 (free)
```

**Cost Optimization**:
- Before (all GPT-4): $300/mo for 50 scans
- After (optimized): $220/mo (27% savings)
  - Recon (GPT-4o-mini): $20/mo (80% of calls)
  - Assessment (Claude Opus): $150/mo (15% of calls)
  - Reports (GPT-4): $50/mo (5% of calls)

**Enterprise Benefits**:
- Air-gapped deployments: Ollama local models (no internet)
- Vendor independence: Not locked to OpenAI/Anthropic
- Experimentation: Test new models (DeepSeek, Qwen) without code changes

**Implementation**: LangChain wrapper for LiteLLM + per-team model config in PostgreSQL

**See**: [LEARNINGS_FROM_CAI.md](./LEARNINGS_FROM_CAI.md#1-multi-model-flexibility-via-litellm) for details

### 6. Prompt Injection Guardrails 🔒

**Critical Security**: Prevent malicious inputs from compromising agents

**Multi-Layered Defense**:

**Layer 1: Input Sanitization**
```python
class PromptGuard:
    INJECTION_PATTERNS = [
        (r"ignore previous instructions", ThreatLevel.DANGEROUS),
        (r"you are now", ThreatLevel.DANGEROUS),
        (r"<\|im_start\|>", ThreatLevel.DANGEROUS),  # Control tokens
    ]

    @classmethod
    def validate_user_input(cls, text: str, team_id: str) -> str:
        threat, patterns = cls.analyze(text)
        if threat == ThreatLevel.DANGEROUS:
            log_security_event(team_id, "prompt_injection_attempt", patterns)
            raise SecurityError("Prompt injection detected")
        return text
```

**Layer 2: Structured Outputs** (Force LLM compliance)
```python
from pydantic import BaseModel

class VulnerabilityFinding(BaseModel):
    """Structured schema (can't inject via free-form text)"""
    severity: Literal["critical", "high", "medium", "low"]
    title: str = Field(..., max_length=200)
    cve: Optional[str] = Field(None, regex=r"CVE-\d{4}-\d{4,7}")

# Force LLM to return JSON schema
llm_with_structure = llm.with_structured_output(VulnerabilityFinding)
```

**Layer 3: Tool Whitelisting**
```python
class ReconAgent:
    allowed_tools = ["subfinder", "nmap", "httpx"]  # Read-only
    requires_approval = False

class ExploitAgent:
    allowed_tools = ["sqlmap", "nuclei"]  # Requires HITL
    requires_approval = True  # Human approval before execution
```

**Benefits**:
- Prevents $100K+ breach costs from malicious inputs
- Security dashboard: "Top teams with injection attempts"
- Compliance: Audit trail of all blocked attempts

**See**: [LEARNINGS_FROM_CAI.md](./LEARNINGS_FROM_CAI.md#2-guardrails-against-prompt-injection) for implementation

### 7. Shared Workspace Pattern (Nexus-Inspired)

**Virtual Filesystem for Agent Collaboration**:
- **Unified Storage API**: All agents read/write to versioned workspace
- **Event-Driven Triggers**: File writes automatically trigger dependent workflows
- **Complete Audit Trail**: Every operation logged with timestamps and agent attribution
- **Backend**: S3/MinIO for object storage, PostgreSQL for metadata
- **Handoff Strategy**: In-memory during scan, persist to Nexus at end (hybrid approach)

**Workspace Organization**:
```
/workspace/{team_id}/{scan_id}/
├── /targets/              # Scope definition
├── /recon/                # Reconnaissance results
│   ├── /subfinder/        # Raw tool outputs
│   ├── /nmap/
│   ├── /httpx/
│   └── handoff.json       # Persistent handoff data (for next scan)
├── /findings/             # Vulnerability scan results
│   ├── /nuclei/
│   ├── /sqlmap/
│   └── handoff.json       # Persistent handoff data
├── /evidence/             # Exploit proofs and artifacts
└── /reports/              # Generated reports
```

**Usage Pattern**:
```python
# Active scan: In-memory handoffs (fast)
state['recon_handoff'] = {"subdomains": [...], "live_hosts": [...]}  # LangGraph state

# Finalization: Persist to Nexus (once)
workspace.write(f"{scan_id}/recon/handoff.json", state['recon_handoff'])

# Next scan: Load historical context
previous = workspace.read(f"{last_scan_id}/recon/handoff.json")
```

### 8. Tool-Agnostic Integration Layer

**Standard Agent Interface**:
```python
class SecurityAgent(ABC):
    @abstractmethod
    def execute(self, input_data: dict) -> dict:
        """Execute primary security tool"""

    @abstractmethod
    def parse_output(self, raw_output: Any) -> List[Finding]:
        """Normalize tool output to standard format"""

    def run(self, input_data: dict) -> List[Finding]:
        """Standard workflow: execute → parse → store"""
        raw = self.execute(input_data)
        findings = self.parse_output(raw)
        self.store_to_workspace(findings)
        return findings
```

**Benefits**:
- Tool substitution without architecture changes
- Unified finding format across all agents
- Easy testing and mocking
- Vendor independence

### 4. Adaptive Workflow Planning

**Dynamic Task Decomposition**:
- Initial plan created based on target scope
- Real-time plan updates as findings emerge
- Escalation triggers for critical vulnerabilities
- Human-in-loop approval for exploitation phases

**Example Flow**:
```
Initial Plan:
  ☐ Discover subdomains
  ☐ Scan for vulnerabilities

Finding: Critical SQLi detected in login endpoint

Updated Plan:
  ☑ Discover subdomains (150 found)
  ☑ Scan for vulnerabilities (12 found)
  ☐ Deep SQL injection analysis (NEW - escalated)
  ☐ Database enumeration (NEW - contingent)
  ☐ Request human approval for data extraction (NEW)
```

### 5. Security-First Design

**Principle of Least Privilege**:
- Agents only have tools/permissions for their specific role
- Exploitation agents require explicit user approval
- API keys stored securely with rotation support
- Rate limiting to prevent abuse/detection

**Compliance & Audit**:
- Complete operation history via Nexus versioning
- ReBAC (Relationship-Based Access Control) for multi-tenant environments
- Exportable audit logs in industry-standard formats
- Data retention policies with automated purging

---

## Core Architecture Layers

### Layer 1: ReconEngine (Attack Surface Discovery)

**Purpose**: Automated discovery and mapping of target attack surface through passive and active reconnaissance.

#### Agent Architecture

**1.1 Subdomain Discovery Agent**

```yaml
Agent Specification:
  Name: SubdomainDiscoveryAgent
  Primary Tool: Subfinder
  Responsibilities:
    - Passive subdomain enumeration from 40+ sources
    - Wildcard filtering and validation
    - Recursive subdomain discovery (if enabled)

  Inputs:
    - Root domains (e.g., target.com, example.org)
    - Scope configuration (depth, source selection)

  Outputs:
    - /workspace/{scan_id}/recon/subfinder/subdomains.json
    - Metadata: source attribution, discovery timestamp

  Integration Pattern:
    - Execution: Go SDK (github.com/projectdiscovery/subfinder/v2)
    - Fallback: CLI with JSON output via subprocess
    - Concurrency: 10 threads (default)

  Coordination:
    - Feeds results to Network Mapping and HTTP Probing agents
    - Writes to Nexus workspace (triggers downstream workflows)
```

**Implementation Example**:
```go
import (
    "github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

type SubdomainAgent struct {
    workspace string
}

func (a *SubdomainAgent) Execute(domain string) ([]string, error) {
    opts := &runner.Options{
        Threads:       10,
        Timeout:       30,
        ResultCallback: a.handleResult,
    }

    runnerInstance, err := runner.NewRunner(opts)
    if err != nil {
        return nil, err
    }

    return runnerInstance.EnumerateSingleDomain(domain, []string{})
}

func (a *SubdomainAgent) StoreResults(subdomains []string, domain string) {
    // Write to Nexus workspace
    nexus.Write(
        fmt.Sprintf("%s/recon/subfinder/%s.json", a.workspace, domain),
        subdomains,
    )
}
```

**1.2 Network Mapping Agent**

```yaml
Agent Specification:
  Name: NetworkMappingAgent
  Primary Tool: Nmap
  Responsibilities:
    - Port scanning (common ports or full range)
    - Service enumeration and version detection
    - OS fingerprinting
    - NSE script execution for advanced probing

  Inputs:
    - IP ranges, CIDR blocks, or host lists
    - Scan profile (stealth, aggressive, default)

  Outputs:
    - /workspace/{scan_id}/recon/nmap/scan-results.xml
    - /workspace/{scan_id}/recon/nmap/services.json (parsed)

  Integration Pattern:
    - Execution: python-nmap library for programmatic control
    - Alternative: Direct CLI execution with XML parsing
    - Callbacks: Real-time progress updates to supervisor

  Scan Profiles:
    - Stealth: -sS -T2 --max-retries 1
    - Default: -sV -sC -T3
    - Aggressive: -sV -sC -A -T4 --script=vuln

  Coordination:
    - Consumes subdomain lists from SubdomainDiscoveryAgent
    - Provides service inventory to VulnerabilityScanningAgent
```

**Implementation Example**:
```python
import nmap
import json

class NetworkMappingAgent:
    def __init__(self, workspace: str):
        self.scanner = nmap.PortScanner()
        self.workspace = workspace

    def execute(self, targets: list, profile: str = "default") -> dict:
        scan_args = {
            "stealth": "-sS -T2 --max-retries 1",
            "default": "-sV -sC -T3",
            "aggressive": "-sV -sC -A -T4 --script=vuln"
        }

        # Execute scan
        self.scanner.scan(
            hosts=" ".join(targets),
            arguments=scan_args[profile]
        )

        # Parse results
        results = self.parse_nmap_output()

        # Store to workspace
        self.store_results(results)

        return results

    def parse_nmap_output(self) -> dict:
        services = []
        for host in self.scanner.all_hosts():
            for proto in self.scanner[host].all_protocols():
                for port in self.scanner[host][proto].keys():
                    service = self.scanner[host][proto][port]
                    services.append({
                        "host": host,
                        "port": port,
                        "protocol": proto,
                        "service": service['name'],
                        "version": service.get('version', 'unknown'),
                        "state": service['state']
                    })
        return {"services": services}

    def store_results(self, results: dict):
        # Write to Nexus workspace
        with open(f"{self.workspace}/recon/nmap/services.json", "w") as f:
            json.dump(results, f, indent=2)
```

**1.3 HTTP Probing Agent**

```yaml
Agent Specification:
  Name: HTTPProbingAgent
  Primary Tool: HTTPx
  Responsibilities:
    - HTTP/HTTPS service validation
    - Technology detection (web frameworks, servers)
    - TLS certificate extraction
    - Response header analysis
    - Content hashing and title extraction

  Inputs:
    - URLs or host lists from subdomain discovery
    - Probe configuration (follow redirects, custom headers)

  Outputs:
    - /workspace/{scan_id}/recon/httpx/live-hosts.json
    - Metadata: status codes, response times, tech stack

  Integration Pattern:
    - Execution: CLI with JSONL output (no official SDK needed)
    - Pipeline-friendly: STDIN/STDOUT for chaining
    - Concurrency: 50 threads (configurable)

  Probe Types:
    - Basic: Status code, content length, server header
    - Extended: TLS info, tech detection, custom headers
    - Full: Screenshots (via headless browser), page hashing

  Coordination:
    - Filters live hosts from subdomain lists
    - Feeds validated targets to VulnerabilityScanningAgent
```

**Implementation Example**:
```python
import subprocess
import json

class HTTPProbingAgent:
    def __init__(self, workspace: str):
        self.workspace = workspace

    def execute(self, hosts: list) -> list:
        # Write hosts to temp file
        with open("/tmp/hosts.txt", "w") as f:
            f.write("\n".join(hosts))

        # Execute httpx
        result = subprocess.run(
            [
                "httpx",
                "-l", "/tmp/hosts.txt",
                "-json",
                "-follow-redirects",
                "-tech-detect",
                "-title",
                "-status-code",
                "-content-length"
            ],
            capture_output=True,
            text=True
        )

        # Parse JSONL output
        live_hosts = []
        for line in result.stdout.strip().split("\n"):
            if line:
                live_hosts.append(json.loads(line))

        # Store results
        self.store_results(live_hosts)

        return live_hosts

    def store_results(self, live_hosts: list):
        with open(f"{self.workspace}/recon/httpx/live-hosts.json", "w") as f:
            json.dump(live_hosts, f, indent=2)
```

**1.4 Recon Coordinator (Supervisor)**

```yaml
Agent Specification:
  Name: ReconCoordinator
  Framework: LangGraph with DeepAgents pattern
  Responsibilities:
    - Task decomposition for reconnaissance phase
    - Agent orchestration (sequential or parallel)
    - Result aggregation and deduplication
    - Attack surface summary generation

  Middleware:
    - TodoListMiddleware: Dynamic task planning
    - SubAgentMiddleware: Spawn specialized agents
    - FilesystemMiddleware: Workspace access

  Workflow Patterns:
    1. Linear: Subdomain → HTTP Probing → Network Mapping
    2. Parallel: Subdomain + Network Mapping (concurrent)
    3. Adaptive: Add deep scanning if initial results exceed threshold

  Decision Logic:
    - If subdomains > 100: Enable parallel HTTP probing
    - If critical services found (HTTPS on 443, SSH on 22): Add banner grabbing
    - If large network detected: Split into batches for rate limiting
```

**Coordinator Implementation**:
```python
from langgraph.prebuilt import create_deep_agent
from langgraph.middleware import TodoListMiddleware, SubAgentMiddleware

recon_coordinator = create_deep_agent(
    name="ReconCoordinator",
    system_prompt="""You orchestrate attack surface discovery by delegating to:
    - SubdomainDiscoveryAgent: Find all subdomains
    - NetworkMappingAgent: Scan networks and enumerate services
    - HTTPProbingAgent: Validate HTTP services and extract metadata

    Plan your approach based on target scope, execute in optimal order,
    and provide comprehensive attack surface summary.""",

    tools=[],  # Supervisor doesn't execute tools directly

    middleware=[
        TodoListMiddleware(),
        SubAgentMiddleware(agents=[
            subdomain_agent,
            network_agent,
            httpx_agent
        ]),
        FilesystemMiddleware(workspace="/workspace")
    ]
)
```

---

### Layer 2: AssessmentEngine (Security Testing & Exploitation)

**Purpose**: Intelligent vulnerability identification and controlled exploitation through LLM-guided decision-making.

#### Agent Architecture

**2.1 Vulnerability Scanning Agent**

```yaml
Agent Specification:
  Name: VulnerabilityScanningAgent
  Primary Tool: Nuclei
  Responsibilities:
    - Template-based vulnerability detection
    - CVE scanning (1000+ templates)
    - Misconfiguration identification
    - Custom vulnerability checks

  Inputs:
    - URLs from HTTP Probing Agent
    - Service information from Network Mapping
    - Template selection criteria (severity, tags, CVE IDs)

  Outputs:
    - /workspace/{scan_id}/findings/nuclei/vulnerabilities.json
    - Severity breakdown, CVSS scores, remediation guidance

  Integration Pattern:
    - Execution: Go SDK for programmatic control
    - Alternative: CLI with JSONL output
    - Template management: Auto-update from nuclei-templates repo

  Scanning Strategies:
    - Auto: Nuclei decides optimal concurrency
    - Host-spray: Spread templates across hosts (better for large targets)
    - Template-spray: Execute all templates per host (better for small targets)

  Coordination:
    - Consumes validated targets from ReconEngine
    - Reports findings to Assessment Supervisor
    - Triggers SQLInjectionAgent for SQLi findings
```

**Implementation Example**:
```python
import subprocess
import json

class VulnerabilityScanningAgent:
    def __init__(self, workspace: str):
        self.workspace = workspace

    def execute(self, targets: list, severity: list = ["critical", "high"]) -> list:
        # Execute nuclei
        result = subprocess.run(
            [
                "nuclei",
                "-l", self.write_targets(targets),
                "-t", "nuclei-templates/",
                "-severity", ",".join(severity),
                "-json",
                "-rate-limit", "150"
            ],
            capture_output=True,
            text=True
        )

        # Parse findings
        findings = []
        for line in result.stdout.strip().split("\n"):
            if line:
                findings.append(json.loads(line))

        # Store and categorize
        categorized = self.categorize_findings(findings)
        self.store_results(categorized)

        return categorized

    def categorize_findings(self, findings: list) -> dict:
        categorized = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": []
        }

        for finding in findings:
            severity = finding.get("info", {}).get("severity", "info").lower()
            categorized[severity].append(finding)

        return categorized

    def store_results(self, findings: dict):
        with open(f"{self.workspace}/findings/nuclei/vulnerabilities.json", "w") as f:
            json.dump(findings, f, indent=2)
```

**2.2 SQL Injection Agent**

```yaml
Agent Specification:
  Name: SQLInjectionAgent
  Primary Tool: SQLMap
  Responsibilities:
    - Automated SQL injection detection
    - Database enumeration (schema, tables, columns)
    - Data extraction (with human approval)
    - WAF/filter evasion (tamper scripts)

  Inputs:
    - URLs with parameters (from Nuclei or manual)
    - Injection hints (POST data, cookies, headers)

  Outputs:
    - /workspace/{scan_id}/findings/sqlmap/injection-results.json
    - /workspace/{scan_id}/evidence/sqlmap/extracted-data/ (if approved)

  Integration Pattern:
    - Execution: REST API via sqlmapapi.py (async support)
    - Alternative: Direct CLI for simple scans
    - Session persistence: Resume interrupted scans

  Exploitation Workflow:
    1. Detection: Test for SQLi vulnerabilities
    2. Enumeration: Extract DBMS version, databases, tables
    3. Human Approval: Request permission for data extraction
    4. Extraction: Download sensitive data (if approved)
    5. Evidence Storage: Store all artifacts in workspace

  Safety Features:
    - Read-only by default (no INSERT/UPDATE/DELETE)
    - Rate limiting to avoid DoS
    - Human-in-loop for data extraction
    - Automatic WAF detection and evasion
```

**Implementation Example**:
```python
import requests
import time

class SQLInjectionAgent:
    def __init__(self, workspace: str, api_url: str = "http://localhost:8775"):
        self.workspace = workspace
        self.api_url = api_url
        self.task_id = None

    def execute(self, target_url: str, data: dict = None) -> dict:
        # Create new task
        self.task_id = self.new_task()

        # Start scan
        self.start_scan(target_url, data)

        # Poll for completion
        while True:
            status = self.get_status()
            if status["status"] == "terminated":
                break
            time.sleep(5)

        # Retrieve results
        results = self.get_data()

        # Store findings
        self.store_results(results)

        return results

    def new_task(self) -> str:
        r = requests.get(f"{self.api_url}/task/new")
        return r.json()["taskid"]

    def start_scan(self, url: str, data: dict = None):
        payload = {
            "url": url,
            "data": data,
            "level": 3,
            "risk": 2,
            "dbs": True  # Enumerate databases
        }
        requests.post(
            f"{self.api_url}/scan/{self.task_id}/start",
            json=payload
        )

    def get_status(self) -> dict:
        r = requests.get(f"{self.api_url}/scan/{self.task_id}/status")
        return r.json()

    def get_data(self) -> dict:
        r = requests.get(f"{self.api_url}/scan/{self.task_id}/data")
        return r.json()

    def request_human_approval(self, database: str) -> bool:
        # Integrate with approval workflow
        print(f"Request approval to extract data from {database}")
        # Return approval decision
        return False  # Default: deny

    def store_results(self, results: dict):
        with open(f"{self.workspace}/findings/sqlmap/injection-results.json", "w") as f:
            json.dump(results, f, indent=2)
```

**2.3 Exploit Coordinator (LLM-Based)**

```yaml
Agent Specification:
  Name: ExploitCoordinator
  Framework: LangGraph + LLM (GPT-4/Claude)
  Responsibilities:
    - Vulnerability prioritization based on exploitability
    - Exploit chain planning (multi-step attacks)
    - Risk assessment for exploitation attempts
    - Human approval workflow coordination

  LLM Capabilities:
    - Analyze vulnerability reports to identify high-value targets
    - Generate custom exploit payloads (within safe boundaries)
    - Plan multi-stage attacks (e.g., SQLi → shell upload → privilege escalation)
    - Provide remediation recommendations

  Tools:
    - read_workspace: Access findings from all agents
    - request_approval: Human-in-loop for critical operations
    - spawn_agent: Delegate to specialized exploitation agents
    - generate_report: Create exploitation summary

  Decision Logic:
    - Prioritize RCE > SQLi > Auth Bypass > XSS
    - Consider CVSS score, public exploits, attack complexity
    - Require approval for: data extraction, file uploads, shell access

  Safety Boundaries:
    - No destructive operations (DROP, DELETE, shutdown)
    - Rate-limited exploit attempts (avoid DoS)
    - Complete audit trail of all actions
```

**Implementation Example**:
```python
from langgraph.prebuilt import create_deep_agent

exploit_coordinator = create_deep_agent(
    name="ExploitCoordinator",
    system_prompt="""You are a security expert coordinating exploitation activities.

    Analyze vulnerability findings from the workspace and:
    1. Prioritize vulnerabilities by severity and exploitability
    2. Plan exploitation strategies (single or multi-stage)
    3. Request human approval for sensitive operations
    4. Coordinate specialized agents (SQLInjectionAgent, etc.)
    5. Document all findings and actions

    CRITICAL: Never perform destructive operations. Always request approval
    before data extraction, file uploads, or shell access.""",

    tools=[
        read_workspace_tool,
        request_approval_tool,
        spawn_sqlmap_agent,
        generate_report_tool
    ],

    middleware=[
        TodoListMiddleware(),
        SubAgentMiddleware(agents=[sqli_agent]),
        FilesystemMiddleware(workspace="/workspace")
    ]
)
```

**2.4 Assessment Supervisor**

```yaml
Agent Specification:
  Name: AssessmentSupervisor
  Framework: LangGraph with Adaptive Planning
  Responsibilities:
    - End-to-end security assessment orchestration
    - Dynamic workflow adjustment based on findings
    - Integration with ReconEngine results
    - Risk-based prioritization

  Workflow Phases:
    1. Target Validation: Verify scope from ReconEngine
    2. Vulnerability Discovery: Launch VulnerabilityScanningAgent
    3. Finding Triage: Categorize by severity and exploitability
    4. Exploitation Planning: Delegate to ExploitCoordinator (if approved)
    5. Reporting: Generate comprehensive assessment report

  Adaptive Behaviors:
    - If critical findings: Escalate to exploitation phase
    - If large attack surface: Prioritize high-value targets
    - If WAF detected: Enable evasion techniques
    - If rate-limited: Implement backoff and retry
```

---

### Layer 3: Intelligence Layer (Cross-Engine)

**Purpose**: Knowledge management, reporting, and continuous monitoring across both engines.

#### Agent Architecture

**3.1 Knowledge Manager (Nexus-Based)**

```yaml
Agent Specification:
  Name: KnowledgeManagerAgent
  Framework: Nexus workspace + Memory API
  Responsibilities:
    - Persistent storage of all scan results
    - Semantic search across historical findings
    - Attack surface diff detection (track changes over time)
    - Cross-scan correlation and trend analysis

  Storage Architecture:
    - Nexus VFS: Versioned, content-addressable storage
    - PostgreSQL: Relational metadata (scans, users, configs)
    - Elasticsearch: Full-text search and analytics

  Key Features:
    - Complete audit trail with time-travel debugging
    - Semantic search: "Find all SQLi vulnerabilities in Q4 2024"
    - Diff reports: "What new subdomains were discovered since last scan?"
    - Knowledge consolidation: Automatic learning loops (ACE pattern)

  API Examples:
    - nx.memory.store("Critical SQLi found in /login", scope="vulns")
    - nx.memory.query(scope="vulns", filter="severity=critical")
    - nx.workspace.diff(snapshot1, snapshot2)
```

**3.2 Report Generator (LLM-Based)**

```yaml
Agent Specification:
  Name: ReportGeneratorAgent
  Framework: LangGraph + LLM
  Responsibilities:
    - Executive summaries for non-technical stakeholders
    - Technical reports with exploit details and remediation
    - Compliance reports (OWASP Top 10, PCI-DSS, etc.)
    - Custom visualizations (charts, graphs, attack timelines)

  Report Types:
    - Executive: High-level risk summary, business impact
    - Technical: Detailed findings, proof-of-concept, remediation
    - Compliance: Mapped to frameworks (OWASP, CWE, MITRE ATT&CK)
    - Delta: Changes since last assessment

  LLM Capabilities:
    - Natural language summarization of findings
    - Risk scoring with business context
    - Remediation prioritization based on exploitability
    - Automated visualization code generation (matplotlib, seaborn)

  Output Formats:
    - PDF: Professional reports with branding
    - JSON: Machine-readable for CI/CD integration
    - Markdown: Developer-friendly documentation
    - CSV: Excel-compatible data export
```

**3.3 Alert Monitor**

```yaml
Agent Specification:
  Name: AlertMonitorAgent
  Framework: Rule engine + optional ML
  Responsibilities:
    - Real-time alerting on critical findings
    - Webhook delivery (Slack, PagerDuty, email)
    - Alert deduplication and suppression
    - Escalation workflows

  Alert Rules:
    - Severity-based: Critical/High findings
    - Condition-based: New CVEs, exposed credentials
    - Threshold-based: Attack surface growth > 20%
    - Custom: User-defined rules (Python expressions)

  Delivery Channels:
    - Webhooks: Slack, Teams, Discord
    - Email: SMTP with HTML templates
    - SMS: Twilio integration
    - PagerDuty: Incident creation

  Features:
    - Deduplication: Same finding within 24h = 1 alert
    - Suppression: User can snooze alerts
    - Escalation: If not acknowledged in 1h, escalate
```

---

## Security Tool Integration

### Integration Patterns Summary

| Tool | Integration Method | Rationale | Pros | Cons |
|------|-------------------|-----------|------|------|
| **Nmap** | Python library (python-nmap) | Mature wrapper, good parsing | Programmatic control, callbacks | Python-only |
| **Nuclei** | Go SDK + CLI fallback | Official SDK for Go, JSON for Python | Native performance, structured output | Multi-language needed |
| **Subfinder** | Go SDK + CLI fallback | Official SDK, pipeline-friendly | Fast, concurrent | Same as Nuclei |
| **HTTPx** | CLI with JSONL output | Simple, no SDK needed | Works anywhere, low overhead | Subprocess overhead |
| **SQLMap** | REST API (sqlmapapi.py) | Async scans, session persistence | Long-running tasks, resumable | Extra service required |

### Tool Workflow Integration

**Typical Assessment Flow**:
```
1. Recon Phase (ReconEngine):
   Subfinder → HTTPx → Nmap
   (Parallel discovery, then validation, then deep scanning)

2. Assessment Phase (AssessmentEngine):
   Nuclei → (If SQLi found) → SQLMap
   (Broad vulnerability scan, then targeted exploitation)

3. Intelligence Phase:
   Knowledge Manager stores all results
   Report Generator creates summaries
   Alert Monitor triggers notifications
```

**Data Flow Between Tools**:
```
Subfinder output (JSON):
  ["sub1.target.com", "sub2.target.com", ...]
  ↓
HTTPx input (list) → HTTPx output (JSONL):
  {"url": "https://sub1.target.com", "status_code": 200, "tech": ["nginx"], ...}
  ↓
Nuclei input (URL list) → Nuclei output (JSONL):
  {"template-id": "cve-2021-12345", "url": "...", "severity": "critical", ...}
  ↓
SQLMap input (vulnerable URL) → SQLMap output (JSON):
  {"injection_point": "id", "dbms": "MySQL", "databases": [...], ...}
```

### Unified Finding Format

**Standard Finding Schema** (all agents normalize to this):
```json
{
  "id": "uuid-v4",
  "scan_id": "scan-uuid",
  "timestamp": "2025-11-15T10:30:00Z",
  "agent": "VulnerabilityScanningAgent",
  "tool": "nuclei",
  "severity": "critical",
  "confidence": "high",
  "title": "SQL Injection in Login Form",
  "description": "Parameter 'id' is vulnerable to boolean-based blind SQL injection",
  "target": {
    "url": "https://target.com/login?id=1",
    "host": "target.com",
    "port": 443,
    "protocol": "https"
  },
  "vulnerability": {
    "cve": "N/A",
    "cwe": "CWE-89",
    "owasp": "A03:2021 - Injection",
    "cvss": {
      "score": 9.8,
      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    }
  },
  "evidence": {
    "request": "GET /login?id=1' AND 1=1-- HTTP/1.1",
    "response": "HTTP/1.1 200 OK...",
    "proof": "Boolean-based injection confirmed via time delays"
  },
  "remediation": {
    "summary": "Use parameterized queries",
    "references": ["https://owasp.org/www-community/vulnerabilities/SQL_Injection"]
  },
  "metadata": {
    "exploitable": true,
    "public_exploit": false,
    "requires_auth": false
  }
}
```

---

## Workflow Orchestration Patterns

### Pattern 1: Linear Pipeline (Basic Scan)

**Use Case**: Straightforward reconnaissance-to-assessment flow for small targets.

```python
# Supervisor creates linear plan
supervisor_plan = """
☐ Discover subdomains for target.com
☐ Probe HTTP services on discovered hosts
☐ Scan live services for vulnerabilities
☐ Generate report
"""

# Execution flow
1. Supervisor → SubdomainAgent
   Input: "target.com"
   Output: 50 subdomains

2. Supervisor → HTTPxAgent
   Input: 50 subdomains from workspace
   Output: 20 live hosts

3. Supervisor → NucleiAgent
   Input: 20 live hosts from workspace
   Output: 5 vulnerabilities

4. Supervisor → ReportGenerator
   Input: All findings from workspace
   Output: PDF report
```

### Pattern 2: Parallel Exploration (Large Targets)

**Use Case**: Comprehensive assessment of large infrastructure with multiple teams.

```python
# Supervisor spawns parallel workflows
supervisor_plan = """
☐ Team 1: Web application scanning (subdomain + httpx + nuclei)
☐ Team 2: Network infrastructure (nmap + service enum)
☐ Team 3: API endpoints (openapi + nuclei API templates)
☐ Aggregate results from all teams
"""

# Parallel execution
Team 1, 2, 3 run concurrently, writing to shared workspace
Supervisor aggregates when all teams complete
```

### Pattern 3: Adaptive Workflow (Critical Finding Escalation)

**Use Case**: Dynamic plan adjustment based on discovered vulnerabilities.

```python
# Initial plan
"""
☐ Run vulnerability scan
"""

# Nuclei finds critical SQLi
# Supervisor updates plan dynamically
"""
☑ Run vulnerability scan (5 findings)
☐ Deep SQL injection analysis (NEW - escalated due to critical finding)
☐ Request human approval for database enumeration (NEW)
☐ Extract database schema if approved (NEW - contingent)
"""

# Supervisor spawns SQLMap agent
# SQLMap confirms exploitability
# Supervisor requests human approval
# If approved, extract data; else, skip and generate report
```

### Pattern 4: Continuous Monitoring (Event-Driven)

**Use Case**: Ongoing attack surface monitoring with automated workflows.

```yaml
# Nexus workflow configuration
workflow:
  name: continuous-monitoring
  schedule: "0 */6 * * *"  # Every 6 hours

  steps:
    - name: subdomain-discovery
      agent: SubdomainAgent
      inputs:
        domains: ["target.com", "example.org"]
      outputs:
        workspace: /workspace/{timestamp}/recon/subfinder/

    - name: diff-detection
      agent: KnowledgeManager
      trigger: after_completion
      action: diff_with_previous

    - name: alert-on-new
      agent: AlertMonitor
      trigger: after_diff
      condition: "new_subdomains > 0"
      action:
        - webhook: "https://hooks.slack.com/..."
        - message: "Discovered {{ new_subdomains }} new subdomains"

    - name: scan-new-hosts
      agent: NucleiAgent
      trigger: after_diff
      inputs:
        targets: "{{ new_subdomains }}"
      condition: "new_subdomains > 0"
```

---

## Technology Stack

### Backend (Python + Go)

**Framework**:
- FastAPI (Python) for REST API and application services
- LangGraph (Python) for agent orchestration
- Go for tool wrappers (Nuclei, Subfinder SDKs)

**Agent Orchestration**:
- LangGraph: Workflow graphs, stateful agents
- LangChain: Tool abstractions, LLM integrations
- DeepAgents patterns: Hierarchical coordination

**Task Queue**:
- Redis: Message broker
- Celery: Distributed task execution
- Python RQ: Simple async tasks

**LLM Providers**:
- OpenAI: GPT-4 for complex reasoning
- Anthropic: Claude for analysis and reporting
- Local: Ollama for cost-sensitive tasks

**Workspace & Memory**:
- Nexus: Virtual filesystem, versioned storage
- PostgreSQL: Scan metadata, user management
- Elasticsearch: Full-text search, analytics

**Security Tools**:
- Nmap: Network scanning (via python-nmap)
- Nuclei: Vulnerability scanning (Go SDK + CLI)
- Subfinder: Subdomain discovery (Go SDK + CLI)
- HTTPx: HTTP probing (CLI with JSON output)
- SQLMap: SQL injection (REST API)

### Frontend (TypeScript) - Next.js SaaS Starter

**Base**: [Next.js SaaS Starter](https://github.com/nextjs/saas-starter) (14.9k ⭐, MIT Licensed)

**Why This Starter**:
- ✅ Production-ready auth, payments, teams out-of-the-box
- ✅ Saves 6-8 weeks of frontend development
- ✅ Battle-tested patterns (14.9k stars, actively maintained)
- ✅ Perfect match for multi-tenant security platform

**Framework**: Next.js 14+ (App Router)

**Authentication & Authorization**:
```yaml
Auth System:
  Provider: NextAuth.js (custom email/password)
  Storage: JWT tokens in HTTP-only cookies (secure)
  Middleware: Global route protection + Server Action validation
  Schema Validation: Zod for input sanitization

RBAC:
  Roles:
    - Owner: Full team access, billing, user management
    - Member: Run scans, view findings
    - Analyst: View-only access (for reporting)
    - Auditor: Read-only audit logs (compliance)

  Implementation:
    - Database-backed roles (PostgreSQL via Drizzle ORM)
    - Middleware checks on every protected route
    - Server Actions validate permissions before execution
```

**Database & ORM**:
```yaml
Database: PostgreSQL (shared with backend)
ORM: Drizzle ORM (type-safe, migration-based)

Schema (Frontend-specific):
  - users: Email, hashed password, role
  - teams: Organization metadata, subscription tier
  - team_members: User-team relationships with roles
  - activity_logs: Audit trail (who did what, when)

Migrations:
  - Setup: pnpm db:setup
  - Migrate: pnpm db:migrate
  - Seed: pnpm db:seed (test users, sample data)
```

**Payment Integration (Stripe)**:
```yaml
Features:
  - Subscription tiers: Free, Pro, Enterprise
  - Checkout: Stripe Checkout integration
  - Portal: Customer self-service (upgrade, cancel, invoices)
  - Webhooks: Real-time subscription status updates

Pricing Model (Example):
  Free:
    - 10 scans/month
    - Basic tools (Subfinder, HTTPx, Nuclei)
    - 7-day data retention

  Pro ($99/month):
    - 100 scans/month
    - All tools (+ Nmap, SQLMap)
    - 90-day data retention
    - Email alerts

  Enterprise ($499/month):
    - Unlimited scans
    - Priority support
    - Custom integrations
    - 1-year data retention
    - SSO (Phase 2)

Implementation:
  - Test: Stripe CLI for localhost webhooks
  - Production: Webhook endpoint /api/stripe/webhook
  - Test Card: 4242 4242 4242 4242
```

**Team & Multi-Tenant Features**:
```yaml
Team Management:
  - CRUD operations on teams (create, invite, remove members)
  - Role-based access control per team
  - Activity logging (audit trail for compliance)

Data Isolation:
  - Each team has separate workspace: /workspace/{team_id}/{scan_id}/
  - Row-level security: Findings tagged with team_id
  - S3 bucket organization: s3://threatweaver/{team_id}/...

Multi-Tenancy Pattern:
  - Shared database, isolated data (team_id foreign key)
  - Shared S3 bucket, prefixed paths (team_id prefix)
  - Shared backend services, request-scoped auth context
```

**UI Components**:
```yaml
Component Library: shadcn/ui (40+ components)
  - Accessible: ARIA-compliant, keyboard navigation
  - Customizable: Tailwind CSS variants
  - Pre-built: Forms, tables, dialogs, dropdowns

Styling: Tailwind CSS + PostCSS
  - Utility-first CSS framework
  - Dark mode support (class-based)
  - Responsive design (mobile-first)

Icons: Lucide React (clean, consistent icon set)
```

**State Management**:
```yaml
Server State: TanStack Query (React Query)
  - Cache API responses (scan results, findings)
  - Automatic refetching on window focus
  - Optimistic updates for better UX

Client State: Zustand (lightweight, no boilerplate)
  - UI state: sidebar open/closed, filters, sort order
  - Scan configuration: target domains, tool selection

Real-time Updates: Server-Sent Events (SSE) or WebSockets
  - Live scan progress: "Nmap scan 45% complete"
  - New findings: Push notifications when critical CVE found
  - Status updates: Agent state changes
```

**Visualization & Dashboards**:
```yaml
Charts: Recharts (built on D3.js)
  - Scan history timeline
  - Vulnerability severity breakdown (pie chart)
  - Attack surface growth over time (line chart)

Workflow Diagrams: React Flow
  - Visualize agent execution graphs
  - Show scan progression (Subfinder → HTTPx → Nuclei)

Custom Visualizations: D3.js (for complex needs)
  - Network topology graphs
  - Subdomain relationship trees
  - Heatmaps for vulnerability density
```

**Project Structure** (Based on SaaS Starter):
```
frontend/
├── app/                      # Next.js App Router
│   ├── (dashboard)/          # Protected routes
│   │   ├── scans/            # Scan management
│   │   ├── findings/         # Vulnerability viewer
│   │   ├── teams/            # Team settings
│   │   └── billing/          # Stripe integration
│   ├── (auth)/               # Login/signup pages
│   └── api/                  # API routes (webhooks)
│
├── components/
│   ├── ui/                   # shadcn/ui components
│   ├── scans/                # Scan-specific components
│   ├── findings/             # Finding cards, tables
│   └── layout/               # Headers, sidebars
│
├── lib/
│   ├── db/                   # Drizzle ORM queries
│   ├── auth/                 # NextAuth config
│   ├── stripe/               # Payment helpers
│   └── api/                  # Backend API client (FastAPI)
│
├── public/                   # Static assets
└── drizzle/                  # Database migrations
```

**Deployment**:
```yaml
Recommended: Vercel (Next.js creators)
  - Zero-config deployment
  - Automatic HTTPS, CDN, edge functions
  - Preview deployments for PRs
  - Cost: $20/month (Pro plan for teams)

Environment Variables:
  - NEXT_PUBLIC_API_URL: Backend FastAPI URL
  - DATABASE_URL: PostgreSQL connection
  - NEXTAUTH_SECRET: JWT signing key
  - STRIPE_SECRET_KEY: Payment processing
  - STRIPE_WEBHOOK_SECRET: Webhook validation

Alternatives:
  - Self-hosted: Docker + Kubernetes (more control)
  - Netlify: Similar to Vercel, good Next.js support
  - AWS Amplify: If already on AWS infrastructure
```

**Backend Integration Pattern**:
```typescript
// Frontend calls FastAPI backend via REST API
// lib/api/scans.ts
export async function startScan(
  teamId: string,
  targets: string[]
): Promise<ScanResponse> {
  const response = await fetch(`${API_URL}/api/v1/scans`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${await getJWT()}`
    },
    body: JSON.stringify({ team_id: teamId, targets })
  });

  return response.json();
}

// Backend validates team_id from JWT, enqueues scan via Celery
```

### Infrastructure & Security Sandboxing

**CRITICAL: Security Tool Sandboxing**

Security tools (Nmap, Nuclei, SQLMap) can:
- Generate malicious network traffic (port scanning, exploit attempts)
- Execute untrusted code (Nuclei templates, SQLMap tamper scripts)
- Access sensitive data (database dumps, credentials)
- Be exploited themselves (vulnerable dependencies, code injection)

**Sandboxing Strategy**:

```yaml
Requirement: Isolated execution environment for all security tools

Option 1: Docker Containers (Recommended for MVP)
  Implementation:
    - Each tool runs in separate Docker container
    - Resource limits: CPU, memory, network bandwidth
    - Read-only filesystem (except /tmp and /workspace)
    - No privileged mode (--privileged=false)
    - Network isolation: Custom bridge network per scan

  Example:
    docker run --rm \
      --cpus="2" \
      --memory="4g" \
      --network="scan-{scan_id}" \
      --read-only \
      --tmpfs /tmp:rw,noexec,nosuid,size=1g \
      -v /workspace/{scan_id}:/workspace:rw \
      threatweaver/nmap:latest \
      nmap -sV target.com

  Pros:
    - ✅ Good isolation (kernel namespaces, cgroups)
    - ✅ Easy to implement (Docker API)
    - ✅ Resource limits enforced
    - ✅ Works on any Docker host

  Cons:
    - ❌ Weaker isolation than VMs (shared kernel)
    - ❌ Escape vulnerabilities possible (rare but exist)
    - ❌ Still shares host network stack

Option 2: Firecracker microVMs (Better Security, Phase 2)
  Implementation:
    - Each scan runs in dedicated microVM (KVM-based)
    - Sub-second boot time (similar to containers)
    - Full VM isolation (separate kernel)
    - Network virtualization (tap devices)

  Example:
    # Via Celery worker
    firecracker_task = run_nmap_in_microvm.delay(
      target="target.com",
      scan_id="abc123",
      timeout=300
    )

  Pros:
    - ✅ Strong isolation (separate kernel)
    - ✅ Fast boot (< 1 second)
    - ✅ Low overhead (5 MiB memory per VM)
    - ✅ Used by AWS Lambda (proven at scale)

  Cons:
    - ❌ More complex setup (KVM, tap networking)
    - ❌ Requires Linux host with KVM
    - ❌ Higher operational complexity

Option 3: gVisor (Compromise, Optional)
  Implementation:
    - User-space kernel (intercepts syscalls)
    - Runs as Docker runtime (drop-in replacement)
    - Better isolation than Docker, faster than VMs

  Pros:
    - ✅ Stronger than containers, faster than VMs
    - ✅ Google uses it for GKE Sandbox
    - ✅ Works with existing Docker/K8s

  Cons:
    - ❌ Some syscalls not supported (compatibility issues)
    - ❌ Performance overhead (~10-20%)

Decision Matrix:
  MVP (Months 1-3):
    - Use Docker containers with strict resource limits
    - Network isolation per scan (Docker networks)
    - Read-only filesystems, tmpfs for /tmp

  Phase 2 (Months 4-6):
    - Evaluate Firecracker if security becomes concern
    - Consider gVisor for Kubernetes deployments
    - Monitor for container escape vulnerabilities

  Enterprise (Months 7+):
    - Firecracker microVMs for high-security customers
    - Dedicated compute per customer (compliance)
    - Optional air-gapped scanning (on-prem appliance)
```

**Network Isolation Strategy**:

```yaml
Problem: Security scans generate malicious traffic that could:
  - Trigger IDS/IPS alerts on your infrastructure
  - Get your IP blacklisted (ISP, Cloudflare, etc.)
  - Violate ToS of cloud providers
  - Legal liability if scanning wrong targets

Solutions:

1. Dedicated Scan Network (MVP):
  Implementation:
    - Separate VPC/subnet for scan workers
    - Egress-only internet gateway
    - No inbound traffic allowed
    - Source IP whitelist with target owners

  Benefits:
    - Isolates scan traffic from application traffic
    - Easy to monitor and rate-limit
    - Can use separate IP ranges

2. Rotating Proxy Pool (Phase 2):
  Implementation:
    - Residential or datacenter proxies
    - Rotate IPs per scan or per target
    - Providers: Luminati, Smartproxy, Oxylabs

  Benefits:
    - Avoid IP blacklisting
    - Distribute traffic across many IPs
    - Looks like organic traffic

  Cost: $100-300/month (10-50 GB traffic)

3. Scope Validation (Critical):
  Implementation:
    - Require proof of ownership (DNS TXT record, file upload)
    - User confirms scope before each scan
    - Rate limiting: Max N scans per hour per user
    - Blocklist: Never scan .gov, .mil, localhost, RFC1918

  Code Example:
    def validate_scan_scope(target: str, team_id: str):
        # Check blocklist
        if is_blocked_domain(target):
            raise ForbiddenError(f"Cannot scan {target}")

        # Require DNS verification for new domains
        if not has_dns_verification(target, team_id):
            raise ValidationError(
                f"Please add TXT record: threatweaver-verify={team_id}"
            )

        # Rate limiting
        recent_scans = count_scans_last_hour(team_id)
        if recent_scans > get_rate_limit(team_id):
            raise RateLimitError("Too many scans, please wait")

        return True
```

**Resource Limits & Quotas**:

```yaml
Per-Scan Limits (Prevent Abuse):
  CPU: 2 cores max
  Memory: 4 GB max
  Disk I/O: 100 MB/s max
  Network: 10 Mbps max (prevents DoS)
  Timeout: 1 hour max (kill runaway scans)

Per-Team Quotas:
  Free Tier:
    - 10 scans/month
    - 100 targets per scan
    - 1 concurrent scan

  Pro Tier:
    - 100 scans/month
    - 1000 targets per scan
    - 5 concurrent scans

  Enterprise:
    - Unlimited scans
    - 10,000 targets per scan
    - 20 concurrent scans

Enforcement:
  - Celery worker limits (CPU, memory via cgroups)
  - Database quota checks before enqueuing
  - Kubernetes resource quotas per namespace
  - Billing webhooks (suspend on payment failure)
```

**Containerization**: Docker + Docker Compose

**Orchestration**: Kubernetes (EKS/GKE/AKS)

**Databases**:
- PostgreSQL: Primary relational database
- Redis: Caching, task queue
- Elasticsearch: Search and analytics

**Object Storage**: S3 / MinIO (evidence, reports, screenshots)

**Monitoring**:
- Prometheus: Metrics collection
- Grafana: Dashboards and alerting
- Sentry: Error tracking

**Logging**:
- uber-go/zap: Structured logging (Go)
- structlog: Structured logging (Python)
- ELK Stack: Log aggregation and analysis

---

## Scalability & Performance

### Horizontal Scaling

**Agent Scaling**:
- Each agent type runs as separate worker pools
- Kubernetes HPA (Horizontal Pod Autoscaler) based on queue depth
- Independent scaling: reconnaissance vs. assessment vs. reporting

**Database Scaling**:
- PostgreSQL: Read replicas for query distribution
- Elasticsearch: Multi-node cluster with sharding
- Redis: Redis Cluster for high availability

**Storage Scaling**:
- Nexus workspace: S3-backed VFS (unlimited storage)
- PostgreSQL: Partitioning for scan history tables
- Elasticsearch: Index lifecycle management (hot → warm → cold → delete)

### Performance Optimization

**Concurrency Control**:
- Nmap: Batched scans with rate limiting
- Nuclei: Template/host spray optimization
- Subfinder: Multi-source parallel enumeration
- HTTPx: Configurable thread pools (default: 50)

**Caching Strategy**:
- Redis: Tool outputs cached for 24h (deduplication)
- Elasticsearch: Aggregation result caching
- CDN: Static assets and reports

**Resource Limits**:
- Per-agent memory limits (Kubernetes resource quotas)
- Scan timeout enforcement (prevent runaway tasks)
- Rate limiting on external APIs (avoid bans)

### Estimated Costs (Production Scale)

| Component | Cost (Small) | Cost (Medium) | Cost (Large) |
|-----------|--------------|---------------|--------------|
| **Compute** (EKS/GKE workers) | $200/month | $800/month | $2,500/month |
| **Databases** (RDS, ES) | $150/month | $500/month | $1,200/month |
| **Storage** (S3) | $30/month | $100/month | $300/month |
| **LLM APIs** (GPT-4/Claude) | $100/month | $300/month | $800/month |
| **Total Infrastructure** | **$480/month** | **$1,700/month** | **$4,800/month** |

**Scale Definitions**:
- Small: 100 scans/month, 10K hosts
- Medium: 500 scans/month, 50K hosts
- Large: 2000 scans/month, 200K+ hosts

---

## Security & Compliance

### Authentication & Authorization

**User Authentication**:
- NextAuth.js: Email/password, OAuth (Google, GitHub)
- JWT tokens with HTTP-only cookies
- MFA support (TOTP via authenticator apps)

**API Authentication**:
- API keys with rotation support
- JWT bearer tokens for service-to-service
- Rate limiting per key (prevents abuse)

**Role-Based Access Control (RBAC)**:
```
Roles:
- Admin: Full system access, user management
- Operator: Run scans, view all findings
- Analyst: View findings, generate reports
- Auditor: Read-only access to audit logs
```

**Relationship-Based Access Control (ReBAC)**:
- Nexus workspace permissions (Google Zanzibar pattern)
- Granular object-level permissions (who can access which scans)
- Team-based isolation for multi-tenant deployments

### Data Protection

**Encryption**:
- At rest: AES-256 for database encryption
- In transit: TLS 1.3 for all network communication
- Secrets: Vault or AWS Secrets Manager

**PII Handling**:
- No collection of personally identifiable information
- Findings redacted before storage (mask emails, IPs if configured)
- GDPR compliance: Right to erasure, data portability

**Audit Trail**:
- Complete operation log via Nexus versioning
- Immutable audit logs (append-only)
- Exportable to SIEM (Splunk, ELK)

### Compliance Frameworks

**Supported Mappings**:
- OWASP Top 10: Automatic vulnerability categorization
- CWE (Common Weakness Enumeration): All findings tagged
- MITRE ATT&CK: Techniques mapped to exploitation phases
- PCI-DSS: Security testing requirements for payment systems

**Reporting**:
- Compliance reports generated automatically
- Gap analysis: What vulnerabilities violate which controls
- Remediation tracking: Close the loop on findings

### Operational Security

**Tool Safety**:
- Read-only by default (no destructive operations)
- Human approval for exploitation phases
- Rate limiting to avoid DoS
- Automatic WAF detection and evasion (respect target limits)

**Secrets Management**:
- All API keys stored in Vault/Secrets Manager
- No hardcoded credentials in code
- Automatic rotation for long-lived tokens

**Incident Response**:
- Automated alerting on critical findings
- Escalation workflows (if not acknowledged, escalate)
- Integration with PagerDuty, Slack, email

---

## Deployment Architecture

### Development Environment

```yaml
Docker Compose Stack:
  services:
    - backend: FastAPI + Celery workers
    - frontend: Next.js dev server
    - postgres: PostgreSQL 15
    - redis: Redis 7
    - elasticsearch: Elasticsearch 8
    - nexus: Nexus workspace server
    - sqlmapapi: SQLMap REST API service

  Volumes:
    - ./workspace:/workspace (Nexus VFS)
    - ./data:/var/lib/postgresql/data

  Networks:
    - threatweaver-network (isolated)
```

### Production (Kubernetes)

```yaml
Kubernetes Architecture:
  Namespaces:
    - threatweaver-app (application services)
    - threatweaver-workers (agent workers)
    - threatweaver-data (databases)

  Deployments:
    - backend-api: 3 replicas (HPA enabled)
    - recon-workers: 5 replicas (ReconEngine agents)
    - assessment-workers: 3 replicas (AssessmentEngine agents)
    - report-workers: 2 replicas (ReportGenerator)
    - frontend: 2 replicas (Next.js)

  StatefulSets:
    - postgres: 1 primary + 2 read replicas
    - elasticsearch: 3 nodes (master, data, ingest)
    - redis: 3 nodes (Redis Cluster)

  Services:
    - backend-api: LoadBalancer (external)
    - frontend: LoadBalancer (external)
    - postgres: ClusterIP (internal)
    - redis: ClusterIP (internal)

  Storage:
    - postgres-data: 100GB SSD (primary), 50GB (replicas)
    - elasticsearch-data: 200GB SSD per node
    - nexus-workspace: S3-backed (unlimited)

  Autoscaling:
    - HPA: Scale based on CPU (70%) and queue depth
    - Cluster Autoscaler: Add nodes when pending pods
```

### CI/CD Pipeline

```yaml
GitHub Actions Workflow:
  triggers:
    - push: main, develop branches
    - pull_request: all branches

  jobs:
    - lint:
        - Python: ruff, mypy, black
        - Go: golangci-lint
        - TypeScript: eslint, prettier

    - test:
        - Backend: pytest with coverage (>80%)
        - Frontend: vitest + Playwright E2E

    - security-scan:
        - SAST: semgrep, bandit
        - Dependency scan: Snyk, Dependabot
        - Secret scan: truffleHog, detect-secrets

    - build:
        - Docker images for backend, frontend, workers
        - Tag: {branch}-{commit-sha}
        - Push to ECR/GCR

    - deploy:
        - Staging: Auto-deploy from develop
        - Production: Manual approval required
        - Helm chart deployment
        - Smoke tests post-deployment
```

---

## Future Evolution

### Phase 1: MVP (Months 1-3)

**Core Capabilities**:
- ✅ ReconEngine: Subdomain, Network, HTTP agents
- ✅ AssessmentEngine: Nuclei, SQLMap integration
- ✅ Basic orchestration: Linear workflows
- ✅ Web dashboard: Scan management, finding viewer
- ✅ Reporting: PDF/JSON export

**Target Scale**: 50 scans/month, 5K hosts per scan

### Phase 2: Intelligence & Automation (Months 4-6)

**Enhancements**:
- 🔄 Knowledge Manager: Semantic search, diff detection
- 🔄 Adaptive workflows: DeepAgents planning patterns
- 🔄 Continuous monitoring: Event-driven scans
- 🔄 Alert system: Webhooks, email, PagerDuty
- 🔄 Advanced reporting: Compliance mappings, visualizations

**Target Scale**: 200 scans/month, 20K hosts per scan

### Phase 3: Advanced Features (Months 7-12)

**New Capabilities**:
- 🔮 Exploit automation: Guided exploitation with LLM
- 🔮 Custom tool integration: Plugin architecture for new tools
- 🔮 Multi-tenant: Team isolation, RBAC, white-labeling
- 🔮 API-first: Public REST API for CI/CD integration
- 🔮 Mobile app: iOS/Android for alerts and quick scans

**Target Scale**: 1000+ scans/month, 100K+ hosts per scan

### Phase 4: Enterprise & Compliance (Months 13-18)

**Enterprise Features**:
- 🔮 SSO integration: Okta, Azure AD, SAML
- 🔮 Advanced RBAC: Custom roles, attribute-based access
- 🔮 Compliance automation: OWASP, PCI-DSS, SOC 2
- 🔮 Multi-region: US, EU, Asia deployments
- 🔮 SLA guarantees: 99.9% uptime, support contracts

### Potential Tool Additions (Phased Roadmap)

**Phase 2: Deep Enumeration & OSINT (Months 4-6)**

**Amass (High-Value Target Deep Enumeration)**:
```yaml
Use Case:
  - After Subfinder identifies initial subdomains
  - LangGraph decides: "This looks like a high-value target"
  - Trigger: Amass for deeper OSINT (passive + active DNS)

Capabilities:
  - 100+ data sources (DNS, certs, web archives, APIs)
  - Graph-based network mapping
  - Advanced DNS techniques (zone transfers, brute force, alterations)

Integration:
  - Execution: CLI via Celery task
  - Output: JSON graph with relationships
  - Storage: /workspace/{scan_id}/recon/amass/graph.json

When to Use:
  - Target is a known high-value company (Fortune 500)
  - Initial subdomain count > 100 (suggests large infrastructure)
  - Human analyst requests deep dive
  - Continuous monitoring (weekly scheduled scans)

Agent: DeepEnumerationAgent (LangGraph-coordinated)
```

**OSINT Tools (theHarvester, SpiderFoot)**:
```yaml
theHarvester (Email & Personnel Discovery):
  Use Case:
    - Social engineering reconnaissance
    - Build target employee database
    - Identify email patterns (firstname.lastname@target.com)

  Capabilities:
    - Email harvesting from search engines
    - Employee names from LinkedIn, Hunter.io
    - Subdomain discovery (secondary to Subfinder)

  Integration:
    - Execution: CLI via Celery
    - Output: /workspace/{scan_id}/osint/theharvester/emails.json
    - Trigger: On-demand or for phishing assessment prep

SpiderFoot (Automated OSINT Framework):
  Use Case:
    - Comprehensive OSINT across 200+ modules
    - Dark web exposure checks
    - Breach data correlation
    - IP/domain reputation analysis

  Capabilities:
    - Passive: Search engines, DNS, WHOIS, Shodan
    - Active: Port scanning, web crawling, service probing
    - Threat Intel: Check against threat feeds

  Integration:
    - Execution: REST API (SpiderFoot HX)
    - Output: JSON findings
    - Storage: /workspace/{scan_id}/osint/spiderfoot/

  When to Use:
    - Pre-engagement reconnaissance (know your target)
    - Continuous monitoring (dark web mentions)
    - Compliance checks (data leak detection)

Agent: OSINTCoordinator (LangGraph, decides which OSINT tools to run)
```

**Workflow Example**:
```
User: "Perform comprehensive assessment of megacorp.com"

LangGraph Supervisor:
  1. Run Subfinder (finds 250 subdomains)
  2. Analyze results: "This is a large, high-value target"
  3. Decision: Trigger Amass for deep enumeration
  4. Run Amass (finds 150 additional subdomains + DNS relationships)
  5. Decision: Run theHarvester for employee emails
  6. theHarvester finds 500 email addresses
  7. Generate OSINT report with network graph + personnel list
  8. Proceed to vulnerability scanning on prioritized targets
```

**Phase 3: Advanced Scanning & Exploitation (Months 7-12)**

**Vulnerability Scanning**:
- OpenVAS: Comprehensive vulnerability scanner (for legacy systems)
- Wapiti: Web application security auditing (alternative to Nuclei)
- Nikto: Web server scanner (quick server-side checks)

**Exploitation**:
- Metasploit: Framework for exploit development (advanced exploitation)
- Burp Suite: Web vulnerability scanner and proxy (manual testing integration)
- Empire/Covenant: Post-exploitation frameworks (C2 after initial access)

**Specialized**:
- WPScan: WordPress security scanner (CMS-specific)
- Retire.js: JavaScript library vulnerability detection (client-side vulns)
- Trivy: Container image scanning (DevSecOps integration)

**Decision Criteria**:
- Add tools only when user base requests them
- Prioritize based on: popularity, ease of integration, ROI
- Each new tool requires: agent wrapper, test suite, documentation

---

## Key Architectural Decisions (Summary)

**1. Dual-Layer Orchestration (Celery + LangGraph)**:
- ✅ **Decision**: Celery for job execution, LangGraph for reasoning
- **Rationale**: Clear separation avoids overlap; Celery handles reliability, LangGraph handles intelligence
- **Trade-off**: Two systems to maintain, but each does one thing exceptionally well

**2. Hybrid Agent Handoffs (In-Memory + Persistent)** 🔄:
- ✅ **Decision**: LangGraph state for active scans, Nexus workspace for historical context
- **Rationale**: Balance speed (in-memory, 3% faster) with persistence (cross-scan knowledge)
- **Implementation**: TypedDict schemas, in-memory handoff nodes, persist to Nexus at scan end
- **Benefits**: Fast workflows + diff detection + trend analysis
- **Inspired by**: CAI's handoff patterns + Nexus workspace model

**3. Multi-Model Flexibility (LiteLLM)** 🎯:
- ✅ **Decision**: Support 300+ models via LiteLLM (not just OpenAI/Anthropic)
- **Rationale**: 27% cost savings, vendor independence, air-gapped support
- **Implementation**: Per-agent model selection, per-team budget caps, automatic fallback
- **Cost**: $300/mo → $220/mo (GPT-4o-mini for recon, Claude Opus for assessment)
- **Inspired by**: CAI's multi-model architecture

**4. Prompt Injection Guardrails** 🔒:
- ✅ **Decision**: Multi-layered defense (input validation, structured outputs, tool whitelisting)
- **Rationale**: Prevent $100K+ breaches from malicious inputs
- **Implementation**: PromptGuard class, Pydantic schemas, per-agent tool restrictions
- **Security**: Audit trail of all injection attempts, security dashboard
- **Inspired by**: CAI's research on AI agent vulnerabilities

**5. MVP-First Storage (PostgreSQL + S3)**:
- ✅ **Decision**: Defer Elasticsearch until proven necessary (Phase 2+)
- **Rationale**: Postgres + S3 handles 90% of MVP needs at fraction of complexity/cost
- **Migration Path**: Add ES when hitting 1000+ scans/month or search becomes bottleneck
- **Handoffs**: In-memory (LangGraph) during scan, persist to Nexus/S3 at end

**6. Docker Sandboxing for Security Tools** 🔒:
- ✅ **Decision**: Docker containers with strict resource limits (MVP), Firecracker microVMs (Phase 2)
- **Rationale**: Security tools can generate malicious traffic, execute untrusted code, be exploited
- **Implementation**: Read-only filesystems, network isolation, CPU/memory limits, 1-hour timeouts
- **Network**: Dedicated VPC for scan workers, scope validation (DNS TXT verification), blocklists
- **Future**: Firecracker for enterprise customers requiring VM-level isolation

**7. Next.js SaaS Starter Frontend** ⭐:
- ✅ **Decision**: Use proven SaaS starter instead of building from scratch
- **Rationale**: Saves 6-8 weeks, production-ready auth/payments/teams, 14.9k stars
- **Features**: Stripe subscriptions (Free/Pro/Enterprise), multi-tenant teams, Drizzle ORM
- **Deployment**: Vercel for frontend ($20/mo), FastAPI backend on AWS/GCP

**8. Phased Tool Integration (Not "Big Bang")**:
- ✅ **Decision**: Start with core 5 tools (Subfinder, Nmap, HTTPx, Nuclei, SQLMap)
- **Rationale**: Prove architecture works, then add Amass/OSINT/Metasploit incrementally
- **Benefits**: Faster MVP, focused testing, user-driven prioritization

**9. Human-in-Loop for Exploitation**:
- ✅ **Decision**: Require approval for SQLMap data extraction, shell access, destructive ops
- **Rationale**: Legal compliance, prevents accidents, builds user trust
- **Implementation**: Database-backed approval system, real-time notifications (Slack, email)
- **Inspired by**: CAI's HITL patterns

---

## Conclusion

ThreatWeaver's architecture provides a scalable, intelligent foundation for automated security testing through:

1. **Hierarchical Multi-Agent Design**: Clear separation between reconnaissance, assessment, and intelligence layers
2. **Industry-Standard Tool Integration**: Leverages best-in-class security tools (Nmap, Nuclei, SQLMap, etc.)
3. **Dual-Layer Orchestration**: Celery executes, LangGraph reasons—no overlap, clear responsibilities
4. **Hybrid Agent Handoffs**: In-memory (fast) + persistent (historical context) = best of both worlds
5. **Multi-Model Flexibility**: LiteLLM supports 300+ models (27% cost savings, vendor independence)
6. **Prompt Injection Guardrails**: Multi-layered defense prevents $100K+ breaches
7. **MVP-First Storage**: PostgreSQL + S3 for simplicity, defer Elasticsearch until needed
8. **Shared Workspace**: Nexus-inspired VFS provides persistent, versioned state over S3
9. **Adaptive Planning**: LLM-powered supervisors adjust workflows based on discovered vulnerabilities
10. **Human-in-Loop**: Database-backed approval system with real-time notifications
11. **Docker Sandboxing**: Isolated tool execution with resource limits and scope validation
12. **Cloud-Native**: Kubernetes-ready, horizontally scalable, production-hardened

**Key Differentiators**:
- ✨ Intelligent coordination vs. simple script chaining (LangGraph supervisors)
- ✨ Persistent knowledge across scan sessions (hybrid handoffs: in-memory + Nexus)
- ✨ Adaptive planning based on findings (dynamic task decomposition, CAI-inspired)
- ✨ Complete audit trail for compliance (immutable logs + time-travel)
- ✨ Cost-optimized LLM usage (multi-model selection, 27% savings)
- ✨ Production-grade security (prompt injection guardrails, Docker sandboxing)
- ✨ Multi-tenant SaaS (Next.js Starter, Stripe subscriptions, RBAC)
- ✨ Extensible plugin architecture (add tools without core changes)
- ✨ Lean MVP approach (Postgres + S3, not Kafka + ES + Kitchen Sink)

**Inspired By**:
- **CAI (Alias Robotics)**: Multi-model flexibility, guardrails, handoffs, HITL patterns
- **LangGraph DeepAgents**: Hierarchical agent coordination, adaptive planning
- **Nexus**: Multi-agent workspace, versioned storage, semantic search
- **Syntar**: Two-engine architecture (Perception + Reasoning)
- **Next.js SaaS Starter**: Production-ready frontend (auth, payments, teams)

**Philosophy**:
> Start simple, learn from proven frameworks (CAI, DeepAgents, Nexus), measure everything, add complexity only when proven necessary by real usage data.

**Positioning**:
> ThreatWeaver is the **production evolution** of AI security automation—taking proven concepts from research tools like CAI and wrapping them with enterprise infrastructure (multi-tenancy, persistence, monitoring, compliance).

This architecture supports both simple single-target scans and complex continuous monitoring programs, scaling from solo security researchers to enterprise red teams. By learning from CAI's proven patterns and combining them with production-grade infrastructure, ThreatWeaver delivers the best of both worlds: **research-validated AI agents** + **enterprise-ready SaaS platform**.

---

## Comparison with Similar Tools

### ThreatWeaver vs CAI (Alias Robotics)

**Quick Summary**:
- **CAI**: Lightweight CLI framework for individual security researchers (pip install, 300+ LLM models, CTF-proven)
- **ThreatWeaver**: Multi-tenant SaaS platform for teams and enterprises (cloud-native, persistent knowledge, continuous monitoring)

**Key Differences**:

| Aspect | ThreatWeaver | CAI |
|--------|--------------|-----|
| **Target Users** | Teams, enterprises, MSPs | Individual researchers, CTF players |
| **Deployment** | Cloud SaaS (Kubernetes) | CLI tool (pip install) |
| **Persistence** | PostgreSQL + S3 (permanent) | None (ephemeral) |
| **Multi-Tenancy** | ✅ Teams, RBAC, billing | ❌ Single-user |
| **Sandboxing** | Docker (MVP), Firecracker (Phase 2) | User responsibility |
| **Continuous Monitoring** | ✅ Scheduled scans, alerts | ❌ One-off tests |
| **Cost** | $0-499/mo (subscription) | $0-100/mo (LLM APIs) |
| **Best For** | Production SaaS, compliance | Research, CTFs, experimentation |

**When to Choose ThreatWeaver**:
- Building multi-tenant SaaS business
- Need persistent knowledge (scan history, trends, diffs)
- Require team collaboration and RBAC
- Want continuous monitoring and alerting
- Enterprise customers (compliance, audit trail, SSO)

**When to Choose CAI**:
- Individual security researcher or pentester
- Need maximum LLM flexibility (300+ models)
- Want low operational overhead (pip install)
- Doing one-off tests, CTFs, or research
- Limited budget ($0-100/mo)

**Detailed Comparison**: See [COMPARISON_WITH_CAI.md](./COMPARISON_WITH_CAI.md) for comprehensive analysis.

**Potential Synergy**: ThreatWeaver could integrate CAI as an agent framework (CAI's flexibility + ThreatWeaver's infrastructure).

---

**Document Version**: 1.2
**Last Updated**: 2025-11-16
**Next Review**: 2025-12-16
**Authors**: ThreatWeaver Architecture Team
**Status**: Living Document (updates tracked in version control)

**Related Documents**:
- [COMPARISON_WITH_CAI.md](./COMPARISON_WITH_CAI.md) - Detailed comparison with Alias Robotics CAI framework
- [LEARNINGS_FROM_CAI.md](./LEARNINGS_FROM_CAI.md) - 10 actionable insights borrowed from CAI (multi-model, guardrails, handoffs, HITL)
- [NEXUS_VS_HANDOFFS.md](./NEXUS_VS_HANDOFFS.md) - Architecture decision: Hybrid handoff strategy (in-memory + persistent)
