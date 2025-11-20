# ThreatWeaver Issue Execution Order

**Last Updated**: 2025-11-18
**Status**: Post-Architecture Update (DeepAgents + Nexus)

This document defines the execution order for GitHub issues based on dependencies and priority.

---

## 📋 Execution Phases

### **Phase 0: Critical Security Foundation (Week 1)** 🔒

**MUST complete before any agent implementation**

| Issue | Title | Priority | Est. | Dependencies | Status |
|-------|-------|----------|------|--------------|--------|
| #23 | Docker Sandboxing for Security Tools | P0 | 3d | None | ⏳ **START HERE** |
| #24 | Scope Validation | P0 | 2d | #23 | ⏳ Next |

**Rationale**: Security tools MUST run in isolated Docker containers. Cannot proceed with agents without sandboxing.

**Deliverables**:
- Docker images: `nmap:latest`, `nuclei:latest`, `subfinder:latest`, `httpx:latest`, `sqlmap:latest`
- Resource limits: CPU (2 cores), Memory (4GB), Network (10 Mbps), Timeout (1 hour)
- Isolated bridge networks per scan
- DNS TXT verification for scope validation
- Blocklist: `.gov`, `.mil`, `localhost`, RFC1918, cloud metadata

---

### **Phase 1: Celery Tools Layer (Week 1-2)** 🛠️

**Create tool wrappers for security tools (Celery tasks)**

| Task | File | Priority | Est. | Dependencies | Status |
|------|------|----------|------|--------------|--------|
| Create Celery tools | `backend/src/agents/tools/celery_tools.py` | P1 | 2d | #23, #24 | ⏳ |
| Create Celery tasks | `backend/src/tasks/security_tools.py` | P1 | 2d | #23 | ⏳ |
| Test tool execution | `backend/tests/test_celery_tools.py` | P1 | 1d | Above | ⏳ |

**Deliverables**:
- `run_subfinder_tool` (LangChain tool)
- `run_httpx_tool` (LangChain tool)
- `run_nmap_tool` (LangChain tool)
- `run_nuclei_tool` (LangChain tool)
- `run_sqlmap_tool` (LangChain tool)
- Celery tasks: `tasks.run_subfinder`, `tasks.run_httpx`, etc.
- Docker execution wrapper

**Example**:
```python
# backend/src/agents/tools/celery_tools.py
from langchain_core.tools import tool
from celery_app import celery

@tool
def run_subfinder(domain: str) -> dict:
    """Execute Subfinder in Docker container via Celery."""
    task = celery.send_task("tasks.run_subfinder", args=[domain])
    result = task.get(timeout=300)  # 5 minutes
    return result
```

---

### **Phase 2: Individual Agents (Week 2-3)** 🤖

**Implement specialized security agents (parallel work possible)**

#### **2A: ReconEngine Agents** (Can work in parallel)

| Issue | Title | Priority | Est. | Dependencies | Status |
|-------|-------|----------|------|--------------|--------|
| #13 | Subfinder Agent | P1 | 2d | Phase 1 | ⏳ |
| #14 | HTTPx Agent | P1 | 2d | Phase 1, #13 | ⏳ |
| #15 | Nmap Agent | P1 | 2d | Phase 1, #14 | ⏳ |

**Deliverables** (Already created factory functions):
- ✅ `create_subfinder_agent()` - `backend/src/agents/agent_factory.py`
- ✅ `create_httpx_agent()` - `backend/src/agents/agent_factory.py`
- ✅ `create_nmap_agent()` - `backend/src/agents/agent_factory.py`
- ⏳ Integration tests per agent
- ⏳ End-to-end workflow tests

**Workflow**:
```
Subfinder → HTTPx → Nmap
(discover) → (probe) → (scan critical hosts)
```

#### **2B: AssessmentEngine Agents** (Can work in parallel)

| Issue | Title | Priority | Est. | Dependencies | Status |
|-------|-------|----------|------|--------------|--------|
| #17 | Nuclei Agent | P1 | 2d | Phase 1, #14 | ⏳ |
| #12 | HITL Approval System | P1 | 3d | #6 (Auth) | ⏳ **CRITICAL for #18** |
| #18 | SQLMap Agent | P1 | 3d | Phase 1, #12, #17 | ⏳ |

**Deliverables**:
- ✅ `create_nuclei_agent()` - Already created
- ⏳ Database-backed approval system (ApprovalRequest model)
- ⏳ Approval API: `POST /api/v1/approvals`, `GET /api/v1/approvals/{id}`
- ✅ `create_sqlmap_agent()` - Already created (requires #12)
- ⏳ HITL workflow integration

**Critical Path**: #12 (HITL) MUST be completed before #18 (SQLMap)

---

### **Phase 3: Coordinator Agents (Week 3-4)** 🎯

**Orchestration layer (supervisors spawning sub-agents)**

| Issue | Title | Priority | Est. | Dependencies | Status |
|-------|-------|----------|------|--------------|--------|
| #11 | Hybrid Agent Handoffs | P1 | 3d | #13-15 (ReconEngine) | ⏳ |
| #16 | Recon Coordinator | P1 | 5d | #11, #13-15 | ⏳ |
| #19 | Assessment Supervisor | P1 | 5d | #11, #12, #17-18 | ⏳ |

**Deliverables**:
- ✅ `create_recon_coordinator()` - Already created
- ⏳ Implement workflow: Subfinder → HTTPx → Nmap (via `task` tool)
- ⏳ Write handoff to `/recon/handoff.json`
- ✅ `create_assessment_supervisor()` - Already created
- ⏳ Read handoff from `/recon/handoff.json`
- ⏳ Implement workflow: Nuclei → (conditional) SQLMap
- ⏳ HITL approval integration
- ⏳ Diff detection (compare with previous scans)

**Workflow**:
```
ReconCoordinator:
  └─> Spawn SubfinderAgent → HTTPxAgent → NmapAgent
  └─> Aggregate results
  └─> Write /recon/handoff.json

AssessmentSupervisor:
  └─> Read /recon/handoff.json
  └─> Spawn NucleiAgent
  └─> IF critical SQLi found: Request HITL approval
  └─> IF approved: Spawn SQLMapAgent
  └─> Write /findings/assessment_report.json
```

---

### **Phase 4: Frontend & Integration (Week 4-5)** 🎨

**User-facing features**

| Issue | Title | Priority | Est. | Dependencies | Status |
|-------|-------|----------|------|--------------|--------|
| #20 | Findings Dashboard | P1 | 3d | #16, #19 | ⏳ |
| #22 | Real-Time Scan Progress | P2 | 2d | #16, #19 | ⏳ |
| #21 | Diff Detection UI | P2 | 2d | #11, #20 | ⏳ |
| #27 | Integration Tests | P1 | 5d | All agents | ⏳ |

**Deliverables**:
- Findings table with severity filters
- Real-time WebSocket updates during scans
- Diff detection visualization (new/removed assets)
- End-to-end integration tests
- Performance benchmarks

---

### **Phase 5: Production Readiness (Week 5-6)** 🚀

**Infrastructure and launch prep**

| Issue | Title | Priority | Est. | Dependencies | Status |
|-------|-------|----------|------|--------------|--------|
| #25 | Production Kubernetes Deployment | P1 | 5d | All above | ⏳ |
| #26 | User Documentation | P1 | 3d | All features | ⏳ |
| #28 | MVP Launch Preparation | P0 | 3d | All above | ⏳ |

**Deliverables**:
- Kubernetes manifests (deployments, services, ingress)
- Helm charts for easy deployment
- CI/CD pipeline (GitHub Actions)
- User documentation (setup, usage, API reference)
- Launch checklist and monitoring setup

---

## 📊 Dependency Graph

```
Phase 0 (Security Foundation)
    #23 Docker Sandboxing ─────┐
    #24 Scope Validation        │
                                ▼
Phase 1 (Celery Tools)
    Celery tools ───────────────┐
    Celery tasks                │
                                ▼
Phase 2 (Individual Agents)
    ┌─────────────┬─────────────┤
    ▼             ▼             ▼
  #13 Subfinder #17 Nuclei   #12 HITL
    │             │             │
    ▼             │             │
  #14 HTTPx       │             │
    │             │             │
    ▼             ▼             ▼
  #15 Nmap      (wait)       #18 SQLMap
    │             │             │
    └─────┬───────┴─────────────┘
          ▼
Phase 3 (Coordinators)
    #11 Handoffs
    #16 ReconCoordinator
    #19 AssessmentSupervisor
          │
          ▼
Phase 4 (Frontend)
    #20 Findings Dashboard
    #22 Real-Time Progress
    #21 Diff Detection UI
    #27 Integration Tests
          │
          ▼
Phase 5 (Production)
    #25 Kubernetes Deployment
    #26 Documentation
    #28 MVP Launch
```

---

## 🎯 Critical Path

**Longest dependency chain** (determines minimum timeline):

```
#23 Docker Sandboxing (3d)
  → Celery Tools (2d)
  → #13 Subfinder (2d)
  → #14 HTTPx (2d)
  → #15 Nmap (2d)
  → #11 Handoffs (3d)
  → #16 Recon Coordinator (5d)
  → #19 Assessment Supervisor (5d)
  → #20 Findings Dashboard (3d)
  → #25 Kubernetes (5d)
  → #28 MVP Launch (3d)

TOTAL: 35 days (7 weeks)
```

**Parallelization**: With 3 engineers, can reduce to **4-5 weeks**.

---

## 🚦 Current Status

### ✅ Completed
- [x] Architecture design (v1.3)
- [x] DeepAgents + Nexus integration
- [x] NexusBackend implementation
- [x] Agent factory functions (all 7 agents)
- [x] Nexus installed (`nexus-ai-fs>=0.5.6`)
- [x] LiteLLM integrated
- [x] DeepAgents installed

### ⏳ In Progress
- [ ] None (ready to start Phase 0)

### 🔜 Next Steps (This Week)
1. **START**: Issue #23 (Docker Sandboxing) - **3 days**
2. **THEN**: Issue #24 (Scope Validation) - **2 days**
3. **THEN**: Celery Tools Layer - **2 days**

---

## 📝 Notes

### Parallel Work Opportunities
- **Week 2**: #13, #14, #15 can be worked on by 3 different engineers
- **Week 3**: #17 and #12 can be parallel (different domains)
- **Week 4**: Frontend (#20, #22, #21) can be parallel with backend integration tests

### Risk Mitigation
- **Blocker**: #12 (HITL) must complete before #18 (SQLMap)
- **Blocker**: Phase 0 (#23, #24) must complete before any agent work
- **Testing**: Integration tests (#27) should run continuously, not just at end

### Resource Allocation
**Recommended team**:
- 1x Security Engineer: #23, #24, Docker sandboxing
- 1x Backend Engineer: Celery tools, agents (#13-18)
- 1x Frontend Engineer: Dashboard (#20, #22, #21)
- 1x DevOps Engineer: #25 (Kubernetes), #28 (Launch prep)

---

## 🎓 References

- **Architecture**: `architecture.md` Section 3 "DeepAgents + Nexus Integration Architecture"
- **Agent Factory**: `backend/src/agents/agent_factory.py`
- **Backend**: `backend/src/agents/backends/nexus_backend.py`
- **Syntar Example**: `/Users/tafeng/syntar/backend/src/reasoning_engine/orchestration/deepagents_orchestrator.py`
- **GitHub Issues**: https://github.com/windoliver/ThreatWeaver/issues
