# Issues 13-19 Analysis & DeepAgents Integration Plan

## Overview of Issues 13-19

### Phase 3: ReconEngine (Issues 13-16)
- **Issue #13**: Implement Subfinder Agent (subdomain discovery)
- **Issue #14**: Implement HTTPx Probing Agent (HTTP service validation)
- **Issue #15**: Implement Nmap Scanning Agent (network scanning)
- **Issue #16**: Create Recon Coordinator (LangGraph) - **Uses DeepAgents!**

### Phase 4: AssessmentEngine (Issues 17-19)
- **Issue #17**: Implement Nuclei Scanning Agent (vulnerability scanning)
- **Issue #18**: Implement SQLMap Injection Agent (SQL injection testing)
- **Issue #19**: Create Assessment Supervisor (LangGraph) - **Uses DeepAgents!**

## DeepAgents Integration Status

### Why You Haven't Seen DeepAgents Yet

**DeepAgents is planned but not yet implemented.** Here's where it fits:

1. **Current Status (✅ Completed)**:
   - Issue #1-3: Infrastructure setup
   - Issue #4: FastAPI backend structure
   - Issue #5: Database models
   - Issue #6: Authentication
   - Issue #7-8: Frontend (Next.js)
   - Issue #9: LiteLLM integration ✅
   - Issue #10: Prompt injection guardrails ✅
   - Issue #11: Hybrid agent handoffs ✅
   - Issue #12: HITL approval system ✅
   - Issue #23: E2B sandbox integration ✅ (just completed!)

2. **DeepAgents Will Be Used In** (⏳ Upcoming):
   - **Issue #16**: Recon Coordinator (LangGraph supervisor)
   - **Issue #19**: Assessment Supervisor (LangGraph supervisor)
   - The "coordinator" and "supervisor" agents ARE DeepAgents implementations!

### DeepAgents Architecture in ThreatWeaver

From `architecture.md`:

```python
from deepagents import create_deep_agent
from nexus.core.nexus_fs import NexusFS

# DeepAgents provides:
# 1. TodoListMiddleware - Dynamic task planning
# 2. SubAgentMiddleware - Spawn sub-agents (Subfinder, HTTPx, Nmap)
# 3. Human-in-the-loop workflows
# 4. LangGraph StateGraph compilation

# Nexus provides:
# - File operations (replaces DeepAgents' FilesystemMiddleware)
# - Memory/persistence layer
# - Workspace management
```

**Key Integration**:
- **DeepAgents**: Agent orchestration, planning, coordination
- **Nexus**: File storage, memory, versioning (already integrated via nexus-ai-fs)
- **LiteLLM**: Multi-model support (Issue #9 - completed)
- **E2B**: Sandbox execution (Issue #23 - just completed)

## Recommended Starting Point

### Option 1: Start with Issue #13 (Subfinder Agent) ⭐ RECOMMENDED

**Why Start Here**:
1. ✅ **Foundation is ready**:
   - E2B sandbox with Subfinder installed
   - LiteLLM integration for LLM calls
   - Nexus workspace already integrated
   - HITL approval system in place

2. ✅ **Simplest agent first**:
   - Subfinder is straightforward (domain → subdomains)
   - No complex dependencies
   - Perfect for establishing the agent pattern

3. ✅ **Build momentum**:
   - Quick win (3 days estimate)
   - Establishes the workflow for Issues #14, #15
   - Tests E2B sandbox integration with real tools

4. ✅ **DeepAgents comes later**:
   - Issues #13-15 are "leaf agents" (no orchestration needed)
   - Issue #16 introduces DeepAgents coordinator
   - Cleaner progression: simple agents → orchestration

**Implementation Path**:
```
Issue #13: Subfinder Agent (3 days)
  ↓
Issue #14: HTTPx Agent (3 days)
  ↓
Issue #15: Nmap Agent (4 days)
  ↓
Issue #16: Recon Coordinator with DeepAgents (5 days)
  ↓ (Now you have the full ReconEngine!)
Issue #17-19: AssessmentEngine
```

### Option 2: Start with Issue #16 (DeepAgents Integration)

**Why This Could Work**:
1. ✅ Get DeepAgents architecture in place first
2. ✅ Create the orchestration pattern early
3. ⚠️ But you'll need mock agents initially (no real tool integrations)

**Challenges**:
- Harder to test without real agents
- More abstract/complex starting point
- DeepAgents learning curve

### Option 3: Parallel Approach (Advanced)

**If you want to see DeepAgents sooner**:
1. **Week 1**: Issue #13 (Subfinder) + Start Issue #16 skeleton
2. **Week 2**: Issue #14 (HTTPx) + Complete Issue #16 orchestration
3. **Week 3**: Issue #15 (Nmap) + Full integration testing

## My Strong Recommendation: Issue #13 (Subfinder Agent)

### Why This Is The Best Choice

1. **Validates E2B Sandbox**: Tests the integration we just built
2. **Establishes Agent Pattern**: Creates the template for Issues #14, #15, #17, #18
3. **Quick Win**: 3 days, concrete output (subdomains found)
4. **Natural Progression**: Simple → complex (agents → orchestration)
5. **DeepAgents Will Make More Sense**: Once you have 3-4 agents built, DeepAgents' orchestration value becomes obvious

### What Issue #13 Looks Like

```python
# backend/src/agents/recon/subfinder_agent.py
from e2b import Sandbox
from nexus.core.nexus_fs import NexusFS
from src.sandbox.factory import SandboxFactory

class SubfinderAgent:
    """Subdomain discovery agent using Subfinder in E2B sandbox."""

    def __init__(self, workspace_path: str):
        self.workspace = NexusFS(workspace_path)
        self.sandbox = SandboxFactory.create("e2b")

    async def execute(self, domain: str) -> list[str]:
        """
        Discover subdomains for target domain.

        Returns:
            List of discovered subdomains
        """
        # Run Subfinder in E2B sandbox
        result = self.sandbox.run_command(f"subfinder -d {domain} -silent")

        # Parse results
        subdomains = result.stdout.strip().split('\n')

        # Store in Nexus workspace
        self.workspace.write(
            "recon/subfinder/subdomains.json",
            {"domain": domain, "subdomains": subdomains, "count": len(subdomains)}
        )

        return subdomains
```

**Task Breakdown for Issue #13**:
1. ✅ E2B sandbox ready (just completed!)
2. ⏳ Create `SubfinderAgent` class (1 day)
3. ⏳ Implement `execute()` method (1 day)
4. ⏳ Write results to Nexus workspace (0.5 days)
5. ⏳ Add error handling, timeouts, tests (0.5 days)

## DeepAgents Reference

**GitHub**: https://github.com/langchain-ai/deepagents

**When We'll Use It**:
- **Issue #16**: `ReconCoordinator` (first DeepAgents implementation)
  - Uses `TodoListMiddleware` for planning
  - Uses `SubAgentMiddleware` to spawn Subfinder/HTTPx/Nmap agents
  - Uses LangGraph for state management

- **Issue #19**: `AssessmentSupervisor` (second DeepAgents implementation)
  - Orchestrates Nuclei and SQLMap agents
  - Conditional escalation logic
  - HITL approval integration

**DeepAgents Dependencies**:
```toml
dependencies = [
    "langchain-ai/deepagents>=0.1.0",
    "langgraph>=0.2.0",
]
```

## Action Plan

### Immediate Next Steps (Recommended)

1. **Start Issue #13: Subfinder Agent** (3 days)
   - Validates E2B sandbox
   - Establishes agent pattern
   - Stores results in Nexus

2. **Then Issue #14: HTTPx Agent** (3 days)
   - Reads from Subfinder output
   - Tests agent chaining
   - HTTP probing logic

3. **Then Issue #15: Nmap Agent** (4 days)
   - Network scanning
   - More complex parsing
   - Docker sandboxing

4. **Then Issue #16: DeepAgents Integration** (5 days)
   - Now you understand what's being orchestrated
   - TodoListMiddleware makes sense
   - SubAgentMiddleware spawns your 3 agents
   - **This is where DeepAgents shines!**

### Alternative: Start with DeepAgents (Issue #16)

If you want to see the orchestration framework first:
1. Install DeepAgents
2. Create skeleton coordinator
3. Use mock agents initially
4. Fill in real agents (Issues #13-15) afterward

**Pros**: See the big picture first
**Cons**: Harder to understand without concrete agents

## Summary

| Issue | Priority | Complexity | Dependencies | Has DeepAgents? |
|-------|----------|------------|--------------|-----------------|
| #13   | High     | Low        | E2B ✅       | No (leaf agent) |
| #14   | High     | Low        | #13          | No (leaf agent) |
| #15   | High     | Medium     | #14          | No (leaf agent) |
| #16   | High     | High       | #13-15       | ✅ YES (coordinator) |
| #17   | High     | Medium     | #16          | No (leaf agent) |
| #18   | High     | High       | #12, #17     | No (leaf agent) |
| #19   | High     | High       | #17-18       | ✅ YES (supervisor) |

## My Recommendation

🎯 **Start with Issue #13 (Subfinder Agent)**

**Rationale**:
1. Validates our E2B work
2. Establishes patterns for other agents
3. Quick win (3 days)
4. DeepAgents makes more sense after you have agents to orchestrate
5. Natural learning curve: concrete → abstract

**Timeline**:
- Week 1: Issues #13, #14 (6 days)
- Week 2: Issues #15, #16 (9 days) ← **DeepAgents introduced here**
- Week 3: Issues #17, #18 (9 days)
- Week 4: Issue #19 (5 days) ← **Second DeepAgents implementation**

By Week 2, you'll implement DeepAgents and truly understand its value! 🚀
