# ThreatWeaver GitHub Issues Roadmap

**Repository**: https://github.com/windoliver/ThreatWeaver
**Based on**: architecture.md v1.2
**Last Updated**: 2025-11-16

---

## 📋 Issue Organization Strategy

### Labels

**Priority:**
- `P0-critical` - MVP blocker, must fix immediately
- `P1-high` - MVP required, top priority
- `P2-medium` - Phase 2 feature
- `P3-low` - Phase 3 or nice-to-have

**Component:**
- `backend` - FastAPI, Python, Celery
- `frontend` - Next.js, TypeScript, UI
- `agent` - LangGraph, agent logic
- `infrastructure` - Docker, K8s, databases
- `security` - Sandboxing, guardrails, auth
- `documentation` - Docs, architecture

**Type:**
- `enhancement` - New feature
- `bug` - Bug fix
- `refactor` - Code improvement
- `research` - Spike, investigation

**Status:**
- `ready` - Ready to work on
- `in-progress` - Currently being worked on
- `blocked` - Waiting on dependency
- `review` - In code review

### Milestones

1. **MVP Foundation** (Weeks 1-2) - Basic infrastructure
2. **CAI Enhancements** (Weeks 3-4) - Multi-model, guardrails, handoffs
3. **ReconEngine** (Weeks 5-6) - Subdomain, Nmap, HTTPx agents
4. **AssessmentEngine** (Weeks 7-8) - Nuclei, SQLMap agents
5. **Frontend** (Weeks 9-10) - Next.js SaaS Starter integration
6. **MVP Launch** (Week 11-12) - Testing, deployment, docs
7. **Phase 2** (Months 4-6) - Advanced features
8. **Phase 3** (Months 7-12) - Enterprise features

---

## 🎯 Phase 0: Repository Setup (Week 0)

### Infrastructure Setup

#### Issue #1: Initialize Monorepo Structure
**Priority**: P0-critical
**Labels**: infrastructure, documentation
**Milestone**: MVP Foundation

**Description**:
Set up monorepo structure with backend, frontend, and docs directories.

**Tasks**:
- [ ] Create `/backend` directory (Python/FastAPI)
- [ ] Create `/frontend` directory (Next.js/TypeScript)
- [ ] Create `/docs` directory (architecture, guides)
- [ ] Create `/infrastructure` directory (Docker, K8s configs)
- [ ] Set up `.gitignore` (Python, Node, IDE files)
- [ ] Create `README.md` with project overview
- [ ] Add `LICENSE` (MIT)
- [ ] Create `CONTRIBUTING.md`

**Acceptance Criteria**:
- [ ] Directory structure matches architecture.md
- [ ] README has badges, quick start, links to docs
- [ ] All standard repo files present

**Estimate**: 1 day

---

#### Issue #2: Set Up Docker Development Environment
**Priority**: P0-critical
**Labels**: infrastructure
**Milestone**: MVP Foundation

**Description**:
Create Docker Compose setup for local development.

**Architecture Reference**: Section 10 (Deployment Architecture)

**Tasks**:
- [ ] Create `docker-compose.yml`
  - PostgreSQL 15
  - Redis 7
  - MinIO (S3-compatible)
- [ ] Create `Dockerfile` for backend
- [ ] Create `Dockerfile` for frontend
- [ ] Add health checks for all services
- [ ] Create `.env.example` with all required variables
- [ ] Write `docs/SETUP.md` with installation instructions

**Acceptance Criteria**:
- [ ] `docker-compose up` starts all services
- [ ] Backend accessible at http://localhost:8000
- [ ] Frontend accessible at http://localhost:3000
- [ ] Database migrations run automatically
- [ ] Setup guide tested by fresh clone

**Estimate**: 2 days

---

#### Issue #3: Set Up CI/CD Pipeline
**Priority**: P1-high
**Labels**: infrastructure
**Milestone**: MVP Foundation

**Description**:
GitHub Actions for automated testing and deployment.

**Tasks**:
- [ ] Create `.github/workflows/backend-ci.yml`
  - Lint (ruff, mypy, black)
  - Tests (pytest with coverage >80%)
  - Security scan (bandit, semgrep)
- [ ] Create `.github/workflows/frontend-ci.yml`
  - Lint (eslint, prettier)
  - Tests (vitest)
  - Type check (tsc --noEmit)
- [ ] Create `.github/workflows/docker-build.yml`
  - Build and push to registry on main
- [ ] Add status badges to README

**Acceptance Criteria**:
- [ ] All PRs require CI to pass
- [ ] Coverage reports generated
- [ ] Docker images tagged with commit SHA

**Estimate**: 2 days

---

## 🚀 Phase 1: MVP Foundation (Weeks 1-2)

### Backend Foundation

#### Issue #4: Set Up FastAPI Backend Structure
**Priority**: P0-critical
**Labels**: backend
**Milestone**: MVP Foundation

**Description**:
Initialize FastAPI application with basic structure.

**Architecture Reference**: Section 7 (Technology Stack - Backend)

**Tasks**:
- [ ] Create `backend/src/main.py` with FastAPI app
- [ ] Set up project structure:
  ```
  backend/src/
  ├── api/              # API routes
  ├── agents/           # Agent implementations
  ├── config/           # Configuration
  ├── db/               # Database models
  ├── security/         # Auth, guardrails
  └── storage/          # Nexus/S3 integration
  ```
- [ ] Install dependencies (`uv` package manager)
- [ ] Create `pyproject.toml` with dependencies
- [ ] Set up structured logging (structlog)
- [ ] Add CORS middleware
- [ ] Create `/health` endpoint

**Dependencies**: Issue #2 (Docker environment)

**Acceptance Criteria**:
- [ ] FastAPI server starts successfully
- [ ] API docs available at `/docs`
- [ ] Health check returns 200 OK
- [ ] Logs are structured JSON

**Estimate**: 2 days

---

#### Issue #5: Set Up Database Models (SQLAlchemy)
**Priority**: P0-critical
**Labels**: backend
**Milestone**: MVP Foundation

**Description**:
Create PostgreSQL schema for scans, teams, findings.

**Architecture Reference**: Section 3 (MVP-First Storage)

**Tasks**:
- [ ] Install SQLAlchemy, Alembic
- [ ] Create models:
  - `User` (id, email, hashed_password, role)
  - `Team` (id, name, subscription_tier, settings)
  - `TeamMember` (team_id, user_id, role)
  - `Scan` (id, team_id, target, status, created_at)
  - `Finding` (id, scan_id, severity, title, description, cve)
  - `ApprovalRequest` (id, scan_id, action, status, expires_at)
- [ ] Create Alembic migrations
- [ ] Add database session dependency
- [ ] Create CRUD utilities

**Dependencies**: Issue #4 (FastAPI structure)

**Acceptance Criteria**:
- [ ] Migrations run successfully
- [ ] All models have foreign keys and indexes
- [ ] CRUD operations work in tests
- [ ] Database schema documented

**Estimate**: 3 days

---

#### Issue #6: Implement User Authentication (NextAuth.js Backend)
**Priority**: P1-high
**Labels**: backend, security
**Milestone**: MVP Foundation

**Description**:
JWT-based authentication for API access.

**Architecture Reference**: Frontend section (Authentication & Authorization)

**Tasks**:
- [ ] Install `python-jose`, `passlib`, `bcrypt`
- [ ] Create `/api/v1/auth/register` endpoint
- [ ] Create `/api/v1/auth/login` endpoint (returns JWT)
- [ ] Create `/api/v1/auth/refresh` endpoint
- [ ] Add `get_current_user` dependency
- [ ] Add `get_current_team` dependency (checks team membership)
- [ ] Implement password hashing
- [ ] Add rate limiting on auth endpoints

**Dependencies**: Issue #5 (Database models)

**Acceptance Criteria**:
- [ ] User can register with email/password
- [ ] User can login and receive JWT
- [ ] JWT expires after 1 hour
- [ ] Refresh tokens work
- [ ] Protected routes return 401 without valid JWT
- [ ] Rate limiting prevents brute force (10 attempts/min)

**Estimate**: 3 days

---

### Frontend Foundation

#### Issue #7: Set Up Next.js SaaS Starter
**Priority**: P1-high
**Labels**: frontend
**Milestone**: MVP Foundation

**Description**:
Initialize frontend based on Next.js SaaS Starter.

**Architecture Reference**: Frontend section (Next.js SaaS Starter)

**Tasks**:
- [ ] Clone Next.js SaaS Starter template
- [ ] Customize branding (ThreatWeaver logo, colors)
- [ ] Set up Drizzle ORM (shared PostgreSQL with backend)
- [ ] Configure NextAuth.js with JWT strategy
- [ ] Set up Stripe integration (test mode)
- [ ] Create subscription tiers:
  - Free: 10 scans/month
  - Pro: 100 scans/month ($99/mo)
  - Enterprise: Unlimited ($499/mo)
- [ ] Add shadcn/ui components
- [ ] Configure Tailwind CSS with ThreatWeaver theme

**Dependencies**: Issue #2 (Docker environment)

**Acceptance Criteria**:
- [ ] Frontend loads at localhost:3000
- [ ] User can sign up and login
- [ ] Dashboard shows after login
- [ ] Stripe checkout works in test mode
- [ ] Dark mode toggle works

**Estimate**: 4 days

---

#### Issue #8: Create Scan Management UI
**Priority**: P1-high
**Labels**: frontend
**Milestone**: MVP Foundation

**Description**:
UI for creating and managing scans.

**Tasks**:
- [ ] Create `/app/(dashboard)/scans/page.tsx`
  - Table of all scans (status, target, created_at)
  - "New Scan" button
- [ ] Create `/app/(dashboard)/scans/new/page.tsx`
  - Form: target domains (textarea), tool selection (checkboxes)
  - Scope validation warning
- [ ] Create `/app/(dashboard)/scans/[id]/page.tsx`
  - Scan details (status, progress, agent logs)
  - Real-time updates via SSE or polling
  - Findings table
- [ ] Create scan status badge component
  - Pending, Running, Completed, Failed
- [ ] Add pagination for scans list

**Dependencies**: Issue #7 (Next.js setup)

**Acceptance Criteria**:
- [ ] User can create new scan
- [ ] User can view scan list
- [ ] User can view scan details
- [ ] Status updates in real-time
- [ ] Mobile responsive

**Estimate**: 5 days

---

## 🎯 Phase 2: CAI-Inspired Enhancements (Weeks 3-4)

### Multi-Model Flexibility

#### Issue #9: Integrate LiteLLM for Multi-Model Support
**Priority**: P1-high
**Labels**: backend, agent
**Milestone**: CAI Enhancements

**Description**:
Replace hard-coded OpenAI/Anthropic with LiteLLM abstraction.

**Architecture Reference**: Section 5 (Multi-Model Flexibility)
**Inspired by**: LEARNINGS_FROM_CAI.md #1

**Tasks**:
- [ ] Install `litellm` package
- [ ] Create `LiteLLMWrapper` for LangChain compatibility
- [ ] Add model configuration to `Team` model:
  ```python
  llm_settings = {
      "recon_model": "gpt-4o-mini",
      "assessment_model": "claude-3-opus",
      "reporting_model": "gpt-4",
      "budget_cap": 500,
      "fallback_model": "ollama/llama3"
  }
  ```
- [ ] Create model selection logic (per-agent type)
- [ ] Implement budget tracking (Prometheus metrics)
- [ ] Add automatic fallback if budget exceeded
- [ ] Create `/api/v1/teams/{id}/llm-settings` endpoint

**Dependencies**: Issue #4, #5 (Backend structure, DB models)

**Acceptance Criteria**:
- [ ] Agents can use any of 300+ models
- [ ] Per-team model configuration works
- [ ] Budget cap enforced (fallback to Ollama)
- [ ] Cost tracking metrics exported
- [ ] 27% cost reduction verified in tests

**Estimate**: 3 days

---

#### Issue #10: Implement Prompt Injection Guardrails
**Priority**: P0-critical (Security)
**Labels**: backend, security, agent
**Milestone**: CAI Enhancements

**Description**:
Multi-layered defense against prompt injection attacks.

**Architecture Reference**: Section 6 (Prompt Injection Guardrails)
**Inspired by**: LEARNINGS_FROM_CAI.md #2

**Tasks**:
- [ ] Create `PromptGuard` class:
  - Layer 1: Input sanitization (regex patterns)
  - Layer 2: Structured outputs (Pydantic schemas)
  - Layer 3: Tool whitelisting (per-agent)
- [ ] Define `INJECTION_PATTERNS` list
- [ ] Add validation to all user input endpoints
- [ ] Create `VulnerabilityFinding` Pydantic model
- [ ] Force LLM structured outputs
- [ ] Log all injection attempts to `security_events` table
- [ ] Create security dashboard query

**Dependencies**: Issue #4 (Backend structure)

**Acceptance Criteria**:
- [ ] Injection patterns blocked (test with examples)
- [ ] Security events logged to database
- [ ] All LLM outputs use Pydantic schemas
- [ ] Agent tools whitelisted
- [ ] Dashboard shows top injection attempts

**Estimate**: 4 days

---

#### Issue #11: Implement Hybrid Agent Handoffs
**Priority**: P1-high
**Labels**: backend, agent
**Milestone**: CAI Enhancements

**Description**:
In-memory handoffs (LangGraph state) + persistent handoffs (Nexus).

**Architecture Reference**: Section 4 (Hybrid Agent Handoff Architecture)
**Inspired by**: NEXUS_VS_HANDOFFS.md

**Tasks**:
- [ ] Define TypedDict schemas:
  - `ReconHandoff`
  - `AssessmentHandoff`
  - `ScanState`
- [ ] Create `HandoffPersistence` class:
  - `save_recon_handoff()`
  - `load_previous_recon_handoff()`
- [ ] Implement handoff analysis nodes:
  - `recon_to_assessment_handoff()`
  - `assessment_to_exploit_handoff()`
- [ ] Add handoff.json to Nexus workspace structure
- [ ] Create diff detection logic (new subdomains, fixed vulns)

**Dependencies**: Issue #4 (Backend structure)

**Acceptance Criteria**:
- [ ] In-memory handoffs work during scan
- [ ] Handoffs persisted to S3 at scan end
- [ ] Next scan loads previous handoff
- [ ] Diff detection returns new/removed items
- [ ] 3% performance improvement measured

**Estimate**: 5 days

---

#### Issue #12: Database-Backed HITL Approval System
**Priority**: P1-high
**Labels**: backend, frontend, security
**Milestone**: CAI Enhancements

**Description**:
Human-in-the-loop approval for exploitation.

**Architecture Reference**: Key Decision #9, LEARNINGS_FROM_CAI.md #4

**Tasks**:
**Backend**:
- [ ] Create `ApprovalRequest` model (already in Issue #5)
- [ ] Create `request_approval()` function (async, polls DB)
- [ ] Create `/api/v1/approvals/{id}/review` endpoint
- [ ] Add Slack/email notification on request
- [ ] Implement 1-hour expiry (auto-deny)

**Frontend**:
- [ ] Create `/app/(dashboard)/approvals/page.tsx`
- [ ] Create `ApprovalCard` component (risk badge, details, approve/deny buttons)
- [ ] Add real-time updates (SSE or WebSockets)
- [ ] Add notification badge in header

**Dependencies**: Issue #5 (DB models), Issue #7 (Next.js)

**Acceptance Criteria**:
- [ ] Agent can request approval
- [ ] User receives notification (Slack + email)
- [ ] User can approve/deny in dashboard
- [ ] Approval expires after 1 hour
- [ ] Agent proceeds or stops based on decision

**Estimate**: 5 days

---

## 🔍 Phase 3: ReconEngine (Weeks 5-6)

### Subdomain Discovery

#### Issue #13: Implement Subfinder Agent
**Priority**: P1-high
**Labels**: backend, agent
**Milestone**: ReconEngine

**Description**:
Subdomain discovery agent using Subfinder.

**Architecture Reference**: Section 3.1 (Layer 1: ReconEngine)

**Tasks**:
- [ ] Create `SubdomainDiscoveryAgent` class
- [ ] Integrate Subfinder Go SDK or CLI
- [ ] Implement `execute()` method
- [ ] Implement `parse_output()` method (normalize to JSON)
- [ ] Write results to Nexus workspace: `/recon/subfinder/subdomains.json`
- [ ] Add concurrency control (10 threads default)
- [ ] Add timeout (5 minutes)
- [ ] Create Celery task wrapper

**Dependencies**: Issue #4 (Backend), Issue #11 (Handoffs)

**Acceptance Criteria**:
- [ ] Can discover subdomains for target domain
- [ ] Results written to Nexus workspace
- [ ] Handles errors gracefully (timeout, no results)
- [ ] Unit tests cover success and failure cases
- [ ] Integration test with real domain

**Estimate**: 3 days

---

#### Issue #14: Implement HTTPx Probing Agent
**Priority**: P1-high
**Labels**: backend, agent
**Milestone**: ReconEngine

**Description**:
HTTP service validation and metadata extraction.

**Architecture Reference**: Section 3.1 (Layer 1: ReconEngine)

**Tasks**:
- [ ] Create `HTTPProbingAgent` class
- [ ] Integrate HTTPx CLI (subprocess + JSON parsing)
- [ ] Implement `execute()` method
- [ ] Extract: status codes, TLS info, tech stack, title
- [ ] Write results to Nexus: `/recon/httpx/live-hosts.json`
- [ ] Add concurrency (50 threads)
- [ ] Add rate limiting (150 req/s)
- [ ] Create Celery task wrapper

**Dependencies**: Issue #13 (Subfinder agent)

**Acceptance Criteria**:
- [ ] Can probe URLs from Subfinder output
- [ ] Extracts metadata (status, tech, TLS)
- [ ] Results written to Nexus
- [ ] Rate limiting enforced
- [ ] Tests with mock HTTPx output

**Estimate**: 3 days

---

#### Issue #15: Implement Nmap Scanning Agent
**Priority**: P1-high
**Labels**: backend, agent
**Milestone**: ReconEngine

**Description**:
Network scanning and service enumeration.

**Architecture Reference**: Section 3.1 (Layer 1: ReconEngine)

**Tasks**:
- [ ] Create `NetworkMappingAgent` class
- [ ] Integrate python-nmap library
- [ ] Implement scan profiles:
  - Stealth: `-sS -T2`
  - Default: `-sV -sC -T3`
  - Aggressive: `-sV -sC -A -T4`
- [ ] Parse XML output to JSON (services list)
- [ ] Write results to Nexus: `/recon/nmap/services.json`
- [ ] Add Docker sandboxing (nmap in container)
- [ ] Create Celery task wrapper

**Dependencies**: Issue #14 (HTTPx agent)

**Acceptance Criteria**:
- [ ] Can scan IP ranges or hosts
- [ ] All 3 scan profiles work
- [ ] Results parsed to JSON correctly
- [ ] Runs in sandboxed container
- [ ] Timeout enforced (1 hour max)

**Estimate**: 4 days

---

#### Issue #16: Create Recon Coordinator (LangGraph)
**Priority**: P1-high
**Labels**: backend, agent
**Milestone**: ReconEngine

**Description**:
LangGraph supervisor orchestrating recon agents.

**Architecture Reference**: Section 3.1.4 (Recon Coordinator)

**Tasks**:
- [ ] Create `ReconCoordinator` agent with LangGraph
- [ ] Add TodoListMiddleware for planning
- [ ] Add SubAgentMiddleware (spawn Subfinder, HTTPx, Nmap)
- [ ] Add FilesystemMiddleware (Nexus workspace access)
- [ ] Implement workflow:
  1. Run Subfinder
  2. Analyze results (handoff node)
  3. Run HTTPx on subdomains
  4. Analyze live hosts (handoff node)
  5. Run Nmap on high-value hosts
- [ ] Add conditional edges (parallel vs sequential)
- [ ] Persist final handoff to Nexus

**Dependencies**: Issues #13, #14, #15 (All recon agents)

**Acceptance Criteria**:
- [ ] Coordinator spawns all 3 agents
- [ ] Handoff analysis works (LLM prioritizes targets)
- [ ] Conditional logic works (skip Nmap if no live hosts)
- [ ] Results aggregated and persisted
- [ ] End-to-end test: domain → full recon report

**Estimate**: 5 days

---

## 🎯 Phase 4: AssessmentEngine (Weeks 7-8)

### Vulnerability Scanning

#### Issue #17: Implement Nuclei Scanning Agent
**Priority**: P1-high
**Labels**: backend, agent
**Milestone**: AssessmentEngine

**Description**:
Template-based vulnerability scanning.

**Architecture Reference**: Section 3.2.1 (Vulnerability Scanning Agent)

**Tasks**:
- [ ] Create `VulnerabilityScanningAgent` class
- [ ] Integrate Nuclei Go SDK or CLI
- [ ] Download nuclei-templates (auto-update)
- [ ] Implement severity filtering (critical, high, medium, low)
- [ ] Parse JSONL output to findings
- [ ] Normalize to `VulnerabilityFinding` Pydantic model
- [ ] Write results to Nexus: `/findings/nuclei/vulnerabilities.json`
- [ ] Add rate limiting (150 req/s)
- [ ] Create Celery task wrapper

**Dependencies**: Issue #16 (Recon Coordinator - provides targets)

**Acceptance Criteria**:
- [ ] Can scan URLs from HTTPx output
- [ ] Filters by severity
- [ ] Results normalized to standard schema
- [ ] Templates auto-update daily
- [ ] Docker sandboxing enforced

**Estimate**: 4 days

---

#### Issue #18: Implement SQLMap Injection Agent
**Priority**: P1-high
**Labels**: backend, agent, security
**Milestone**: AssessmentEngine

**Description**:
SQL injection detection and exploitation (with HITL approval).

**Architecture Reference**: Section 3.2.2 (SQL Injection Agent)

**Tasks**:
- [ ] Create `SQLInjectionAgent` class
- [ ] Start SQLMap REST API (`sqlmapapi.py`)
- [ ] Implement async scanning (poll for completion)
- [ ] Create HITL approval request before data extraction
- [ ] Implement safe defaults (read-only, no destructive ops)
- [ ] Parse results (injection points, DBMS version, databases)
- [ ] Write results to Nexus: `/findings/sqlmap/injection-results.json`
- [ ] Create Celery task wrapper

**Dependencies**: Issue #12 (HITL approval), Issue #17 (Nuclei - finds SQLi)

**Acceptance Criteria**:
- [ ] Can test URLs for SQL injection
- [ ] HITL approval required for data extraction
- [ ] Results include injection point and DBMS info
- [ ] Timeout enforced (1 hour)
- [ ] Evidence stored in Nexus

**Estimate**: 5 days

---

#### Issue #19: Create Assessment Supervisor (LangGraph)
**Priority**: P1-high
**Labels**: backend, agent
**Milestone**: AssessmentEngine

**Description**:
LangGraph supervisor orchestrating assessment agents.

**Architecture Reference**: Section 3.2.4 (Assessment Supervisor)

**Tasks**:
- [ ] Create `AssessmentSupervisor` agent with LangGraph
- [ ] Add TodoListMiddleware for adaptive planning
- [ ] Add SubAgentMiddleware (spawn Nuclei, SQLMap)
- [ ] Implement workflow:
  1. Load targets from ReconHandoff
  2. Run Nuclei scan
  3. Analyze findings (handoff node)
  4. If SQLi found: spawn SQLMapAgent
  5. Request HITL approval
  6. Persist AssessmentHandoff
- [ ] Add conditional escalation (critical finding → deep test)
- [ ] Integrate with ApprovalRequest system

**Dependencies**: Issues #17, #18 (Nuclei, SQLMap agents)

**Acceptance Criteria**:
- [ ] Supervisor spawns Nuclei agent
- [ ] Conditional escalation works (SQLi → SQLMap)
- [ ] HITL approval requested for exploitation
- [ ] AssessmentHandoff persisted to Nexus
- [ ] End-to-end test: targets → vulnerabilities report

**Estimate**: 5 days

---

## 📊 Phase 5: Frontend & Reporting (Weeks 9-10)

### Dashboard & Visualization

#### Issue #20: Create Findings Dashboard
**Priority**: P1-high
**Labels**: frontend
**Milestone**: Frontend

**Description**:
Vulnerability findings viewer with filtering and sorting.

**Tasks**:
- [ ] Create `/app/(dashboard)/scans/[id]/findings/page.tsx`
- [ ] Create `FindingCard` component:
  - Severity badge (critical, high, medium, low)
  - Title, description, CVE, CWE
  - Target URL
  - Proof/evidence (collapsible)
  - Remediation recommendations
- [ ] Add filters:
  - Severity (multi-select)
  - Tool (Nuclei, SQLMap, Nmap)
  - Status (new, confirmed, false-positive, fixed)
- [ ] Add sorting (severity, created_at)
- [ ] Add export (JSON, CSV, PDF)
- [ ] Add pagination

**Dependencies**: Issue #8 (Scan management UI)

**Acceptance Criteria**:
- [ ] All findings displayed in cards
- [ ] Filters work correctly
- [ ] Sorting works
- [ ] Export to JSON/CSV works
- [ ] Mobile responsive

**Estimate**: 4 days

---

#### Issue #21: Create Diff Detection UI
**Priority**: P2-medium
**Labels**: frontend
**Milestone**: Frontend

**Description**:
Show changes between scans (new subdomains, fixed vulns).

**Architecture Reference**: Section 4 (Hybrid Handoffs - Diff Detection)

**Tasks**:
- [ ] Create `/app/(dashboard)/scans/[id]/diff/page.tsx`
- [ ] Create diff API endpoint: `/api/v1/scans/{id}/diff`
  - Load current and previous handoffs
  - Calculate diff (added, removed, fixed, new_vulns)
- [ ] Create diff visualization:
  - New subdomains (green badge)
  - Removed subdomains (red badge)
  - Fixed vulnerabilities (green badge)
  - New vulnerabilities (red badge)
- [ ] Add timeline chart (Recharts)
- [ ] Add attack surface growth metric

**Dependencies**: Issue #11 (Handoff implementation), Issue #20 (Findings UI)

**Acceptance Criteria**:
- [ ] Shows new vs removed subdomains
- [ ] Shows fixed vs new vulnerabilities
- [ ] Timeline chart displays growth
- [ ] Only works if previous scan exists

**Estimate**: 3 days

---

#### Issue #22: Implement Real-Time Scan Progress
**Priority**: P2-medium
**Labels**: backend, frontend
**Milestone**: Frontend

**Description**:
Live updates during scan execution.

**Tasks**:
**Backend**:
- [ ] Create `/api/v1/scans/{id}/progress` SSE endpoint
- [ ] Update scan status in DB:
  - `pending`, `running`, `completed`, `failed`
  - Current step (e.g., "Running Subfinder")
  - Progress percentage
- [ ] Emit events on agent completion

**Frontend**:
- [ ] Add SSE subscription in scan details page
- [ ] Create progress bar component
- [ ] Show current agent step
- [ ] Show agent logs (live stream)
- [ ] Add "Cancel Scan" button

**Dependencies**: Issue #8 (Scan UI), Issue #16, #19 (Coordinators)

**Acceptance Criteria**:
- [ ] Progress bar updates in real-time
- [ ] Current step displayed
- [ ] Logs stream live
- [ ] Cancel button works (stops Celery task)

**Estimate**: 4 days

---

## 🔒 Phase 6: Security & Infrastructure (Weeks 11-12)

### Docker Sandboxing

#### Issue #23: Implement Docker Sandboxing for Security Tools
**Priority**: P0-critical (Security)
**Labels**: infrastructure, security
**Milestone**: MVP Launch

**Description**:
Run all security tools in isolated Docker containers.

**Architecture Reference**: Infrastructure & Security Sandboxing section

**Tasks**:
- [ ] Create tool Docker images:
  - `threatweaver/nmap:latest`
  - `threatweaver/nuclei:latest`
  - `threatweaver/subfinder:latest`
  - `threatweaver/httpx:latest`
  - `threatweaver/sqlmap:latest`
- [ ] Configure resource limits:
  - CPU: 2 cores
  - Memory: 4GB
  - Network: 10 Mbps
  - Timeout: 1 hour
- [ ] Add read-only filesystems (except /tmp, /workspace)
- [ ] Create isolated bridge network per scan
- [ ] Implement Docker execution wrapper in agents

**Dependencies**: Issues #13-15, #17-18 (All agents)

**Acceptance Criteria**:
- [ ] All tools run in containers
- [ ] Resource limits enforced
- [ ] Containers isolated per scan
- [ ] Workspace mounted read-write
- [ ] Containers auto-cleanup after scan

**Estimate**: 5 days

---

#### Issue #24: Implement Scope Validation
**Priority**: P0-critical (Legal)
**Labels**: backend, security
**Milestone**: MVP Launch

**Description**:
Verify target ownership before scanning.

**Architecture Reference**: Network Isolation Strategy

**Tasks**:
- [ ] Create DNS TXT verification:
  - Generate verification token per team
  - Check for `threatweaver-verify={team_id}` TXT record
- [ ] Create blocklist:
  - .gov, .mil domains
  - localhost, 127.0.0.1, RFC1918 IPs
  - Cloud provider metadata endpoints
- [ ] Add validation to scan creation endpoint
- [ ] Create `/api/v1/teams/{id}/verification` endpoint
- [ ] Add verification status to team settings

**Dependencies**: Issue #6 (Auth), Issue #8 (Scan UI)

**Acceptance Criteria**:
- [ ] Cannot scan without DNS verification
- [ ] Blocklisted domains rejected
- [ ] Verification status shown in UI
- [ ] Clear error messages for blocked scans

**Estimate**: 3 days

---

#### Issue #25: Set Up Production Kubernetes Deployment
**Priority**: P1-high
**Labels**: infrastructure
**Milestone**: MVP Launch

**Description**:
Kubernetes manifests for production deployment.

**Architecture Reference**: Section 10 (Deployment Architecture - Kubernetes)

**Tasks**:
- [ ] Create Helm chart for ThreatWeaver
- [ ] Create Kubernetes manifests:
  - `backend-deployment.yaml` (3 replicas, HPA)
  - `frontend-deployment.yaml` (2 replicas)
  - `celery-worker-deployment.yaml` (5 replicas)
  - `postgres-statefulset.yaml` (1 primary + 2 read replicas)
  - `redis-statefulset.yaml` (3 nodes, Redis Cluster)
- [ ] Configure ingress (NGINX or Traefik)
- [ ] Add TLS (cert-manager)
- [ ] Configure persistent volumes (S3 for Nexus)
- [ ] Add monitoring (Prometheus, Grafana)

**Dependencies**: Issues #2, #23 (Docker setup, sandboxing)

**Acceptance Criteria**:
- [ ] Helm chart installs successfully
- [ ] All services healthy
- [ ] TLS certificates provisioned
- [ ] Horizontal autoscaling works
- [ ] Prometheus metrics exported

**Estimate**: 5 days

---

## 📚 Phase 7: Documentation & Testing (Week 12)

#### Issue #26: Write User Documentation
**Priority**: P1-high
**Labels**: documentation
**Milestone**: MVP Launch

**Description**:
Complete user guide and API documentation.

**Tasks**:
- [ ] Update README.md with:
  - Features list
  - Architecture diagram
  - Quick start guide
  - Screenshots
- [ ] Create `docs/USER_GUIDE.md`:
  - Creating scans
  - Understanding findings
  - Approval workflow
  - Diff detection
- [ ] Create `docs/API_REFERENCE.md`:
  - All endpoints documented
  - Request/response examples
  - Authentication guide
- [ ] Create `docs/DEPLOYMENT.md`:
  - Docker Compose setup
  - Kubernetes deployment
  - Environment variables
- [ ] Record demo video (5 min walkthrough)

**Acceptance Criteria**:
- [ ] New user can follow quick start successfully
- [ ] All API endpoints documented
- [ ] Deployment guide tested by external user

**Estimate**: 3 days

---

#### Issue #27: Write Integration Tests
**Priority**: P1-high
**Labels**: backend, testing
**Milestone**: MVP Launch

**Description**:
End-to-end integration tests for critical workflows.

**Tasks**:
- [ ] Create test suite in `backend/tests/integration/`
- [ ] Test workflows:
  - User registration → login → JWT works
  - Create scan → agents run → findings saved
  - Approval request → user approves → agent proceeds
  - Diff detection → compares scans → shows changes
- [ ] Use pytest fixtures for test data
- [ ] Mock external services (Subfinder, Nuclei)
- [ ] Add to CI pipeline

**Dependencies**: All agent issues (#13-19)

**Acceptance Criteria**:
- [ ] All critical workflows tested
- [ ] Tests run in CI
- [ ] Coverage >80%
- [ ] Tests pass consistently

**Estimate**: 4 days

---

## 🚀 MVP Launch Checklist (Week 12)

#### Issue #28: MVP Launch Preparation
**Priority**: P0-critical
**Labels**: infrastructure, documentation
**Milestone**: MVP Launch

**Description**:
Final pre-launch tasks.

**Tasks**:
- [ ] Security audit:
  - Penetration test
  - Dependency scan (Snyk)
  - Secret scan (TruffleHog)
- [ ] Performance testing:
  - Load test (100 concurrent scans)
  - Database query optimization
  - Frontend Lighthouse score >90
- [ ] Legal compliance:
  - Add Terms of Service
  - Add Privacy Policy
  - GDPR compliance checklist
- [ ] Marketing:
  - Create landing page
  - Write launch blog post
  - Prepare social media posts
- [ ] Monitoring:
  - Set up error tracking (Sentry)
  - Configure alerts (PagerDuty)
  - Create runbooks

**Acceptance Criteria**:
- [ ] All security issues resolved
- [ ] Performance benchmarks met
- [ ] Legal docs published
- [ ] Launch blog post ready
- [ ] Monitoring fully operational

**Estimate**: 5 days

---

## 📅 Timeline Summary

**Weeks 1-2**: Foundation (Issues #1-8) - Infrastructure, backend, frontend setup
**Weeks 3-4**: CAI Enhancements (Issues #9-12) - Multi-model, guardrails, handoffs, HITL
**Weeks 5-6**: ReconEngine (Issues #13-16) - Subfinder, HTTPx, Nmap, coordinator
**Weeks 7-8**: AssessmentEngine (Issues #17-19) - Nuclei, SQLMap, supervisor
**Weeks 9-10**: Frontend (Issues #20-22) - Findings UI, diff detection, real-time updates
**Weeks 11-12**: Security & Launch (Issues #23-28) - Sandboxing, K8s, docs, testing

**Total**: 28 issues, 12 weeks to MVP

---

## 🏷️ Issue Tagging Convention

**Titles**:
- `[INFRA] Issue Title` - Infrastructure
- `[BACKEND] Issue Title` - Backend
- `[FRONTEND] Issue Title` - Frontend
- `[AGENT] Issue Title` - Agent implementation
- `[SECURITY] Issue Title` - Security feature
- `[DOCS] Issue Title` - Documentation

**Labels** (apply multiple):
- Priority: `P0-critical`, `P1-high`, `P2-medium`, `P3-low`
- Component: `backend`, `frontend`, `agent`, `infrastructure`, `security`, `documentation`
- Type: `enhancement`, `bug`, `refactor`, `research`
- Status: `ready`, `in-progress`, `blocked`, `review`

**Example**:
```
Title: [BACKEND] Implement Prompt Injection Guardrails
Labels: P0-critical, backend, security, enhancement, ready
Milestone: CAI Enhancements
```

---

## 📊 Progress Tracking

**GitHub Projects**:
- Create "ThreatWeaver MVP" project board
- Columns: Backlog, Ready, In Progress, Review, Done
- Add all 28 issues to project
- Track velocity (issues completed per week)

**Metrics**:
- Burndown chart (issues remaining over time)
- Code coverage (target >80%)
- Test pass rate (target 100%)
- Deployment frequency

---

## 🎯 Next Steps

1. **Create GitHub repo** (if not exists): `windoliver/ThreatWeaver`
2. **Enable GitHub Issues** in repo settings
3. **Create all 28 issues** using this roadmap
4. **Create milestones** (MVP Foundation, CAI Enhancements, etc.)
5. **Create project board** for tracking
6. **Assign initial issues** to team members
7. **Set up CI/CD** (Issue #3)
8. **Start with Issue #1** (Repository setup)

**Ready to execute!** 🚀
