# ThreatWeaver

**Multi-Agent Cybersecurity Automation Platform**

[![Version](https://img.shields.io/badge/version-0.1.0--alpha-blue.svg)](https://github.com/windoliver/ThreatWeaver)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![TypeScript](https://img.shields.io/badge/typescript-5.0+-blue.svg)](https://www.typescriptlang.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Backend CI](https://github.com/windoliver/ThreatWeaver/actions/workflows/backend-ci.yml/badge.svg)](https://github.com/windoliver/ThreatWeaver/actions/workflows/backend-ci.yml)
[![Frontend CI](https://github.com/windoliver/ThreatWeaver/actions/workflows/frontend-ci.yml/badge.svg)](https://github.com/windoliver/ThreatWeaver/actions/workflows/frontend-ci.yml)
[![Docker Build](https://github.com/windoliver/ThreatWeaver/actions/workflows/docker-build.yml/badge.svg)](https://github.com/windoliver/ThreatWeaver/actions/workflows/docker-build.yml)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

ThreatWeaver is a **cloud-native, multi-tenant SaaS platform** that provides comprehensive offensive security automation through intelligent orchestration of industry-standard security tools. Leveraging AI agents powered by LangGraph and inspired by research frameworks like CAI, ThreatWeaver delivers adaptive, end-to-end security assessments.

---

## 🎯 Key Features

- **Two-Engine Architecture**:
  - **ReconEngine**: Automated attack surface discovery (Subfinder, Nmap, HTTPx)
  - **AssessmentEngine**: Intelligent vulnerability scanning (Nuclei, SQLMap) with LLM-guided exploitation

- **AI-Powered Intelligence**:
  - Multi-model flexibility (300+ LLMs via LiteLLM)
  - Adaptive planning (LangGraph DeepAgents pattern)
  - Hybrid agent handoffs (in-memory + persistent)
  - Prompt injection guardrails (multi-layered defense)

- **Multi-Tenant SaaS**:
  - Next.js frontend (shadcn/ui, Tailwind CSS)
  - Stripe subscriptions (Free, Pro, Enterprise)
  - Team collaboration with RBAC
  - Complete audit trail

- **Continuous Monitoring**:
  - Scheduled scans with diff detection
  - Real-time alerts (Slack, email, PagerDuty)
  - Attack surface growth tracking
  - "50 new subdomains since last scan"

- **Production-Ready**:
  - Docker sandboxing (Firecracker microVMs in Phase 2)
  - Kubernetes deployment
  - PostgreSQL + S3 storage
  - Human-in-the-loop approval for exploitation

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────┐
│              User Interface (Next.js)                     │
│  Dashboard · Scans · Findings · Approvals · Billing      │
└──────────────────────────────────────────────────────────┘
                            ▼
┌──────────────────────────────────────────────────────────┐
│          Multi-Agent Orchestration (LangGraph)           │
│  ┌────────────────┐        ┌────────────────────────┐   │
│  │  ReconEngine   │        │  AssessmentEngine      │   │
│  │  (Discovery)   │   →    │  (Exploitation)        │   │
│  └────────────────┘        └────────────────────────┘   │
└──────────────────────────────────────────────────────────┘
                            ▼
┌──────────────────────────────────────────────────────────┐
│       Task Execution (Celery + Docker Sandboxing)        │
│  Subfinder · Nmap · HTTPx · Nuclei · SQLMap              │
└──────────────────────────────────────────────────────────┘
                            ▼
┌──────────────────────────────────────────────────────────┐
│        Storage (PostgreSQL + S3 + Nexus Workspace)       │
│  Scans · Findings · Handoffs · Evidence · Reports        │
└──────────────────────────────────────────────────────────┘
```

**See**: [architecture.md](./architecture.md) for comprehensive design document

---

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose
- Python 3.11+ (for backend development)
- Node.js 18+ (for frontend development)
- Git

### 1. Clone Repository

```bash
git clone https://github.com/windoliver/ThreatWeaver.git
cd ThreatWeaver
```

### 2. Start Infrastructure

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your API keys
# - OPENAI_API_KEY (or Anthropic, Ollama)
# - STRIPE_SECRET_KEY (test mode)
# - Database credentials

# Start all services
docker-compose up -d

# Check status
docker-compose ps
```

### 3. Access Dashboard

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs

**Default credentials** (development):
- Email: `test@test.com`
- Password: `admin123`

---

## 📊 Usage Example

### Create Your First Scan

```bash
# Via CLI (using httpie)
http POST http://localhost:8000/api/v1/scans \
  Authorization:"Bearer $JWT_TOKEN" \
  targets:='["example.com"]' \
  tools:='["subfinder", "httpx", "nuclei"]'

# Response
{
  "scan_id": "abc123",
  "status": "pending",
  "created_at": "2025-11-16T10:00:00Z"
}

# Monitor progress
http GET http://localhost:8000/api/v1/scans/abc123
```

### View Results

**Web Dashboard**:
1. Navigate to http://localhost:3000/scans/abc123
2. View live progress (real-time updates)
3. Review findings table (severity, CVE, remediation)
4. Approve exploitation (SQLMap data extraction)
5. Export report (PDF, JSON, CSV)

**Diff Detection** (second scan):
```bash
# Run second scan
http POST http://localhost:8000/api/v1/scans \
  targets:='["example.com"]'

# View changes
http GET http://localhost:8000/api/v1/scans/def456/diff

# Response
{
  "new_subdomains": ["api.example.com", "staging.example.com"],
  "removed_subdomains": ["old.example.com"],
  "new_vulnerabilities": 3,
  "fixed_vulnerabilities": 1
}
```

---

## 🛠️ Tech Stack

### Backend (Python)
- **Framework**: FastAPI
- **Agent Orchestration**: LangGraph, LangChain
- **Task Queue**: Celery + Redis
- **Database**: PostgreSQL 15, SQLAlchemy
- **Storage**: S3/MinIO (Nexus VFS)
- **LLM**: LiteLLM (300+ models)
- **Security Tools**: Nmap, Nuclei, Subfinder, HTTPx, SQLMap

### Frontend (TypeScript)
- **Framework**: Next.js 14+ (App Router)
- **UI**: shadcn/ui, Tailwind CSS, Radix UI
- **Auth**: NextAuth.js (JWT + HTTP-only cookies)
- **Payments**: Stripe
- **ORM**: Drizzle ORM
- **State**: TanStack Query, Zustand

### Infrastructure
- **Containerization**: Docker, Docker Compose
- **Orchestration**: Kubernetes (Helm charts)
- **Monitoring**: Prometheus, Grafana
- **Logging**: Zap (Go), structlog (Python)

---

## 📚 Documentation

- **[Architecture](./architecture.md)** - Complete system design (96KB, 50,000 words)
- **[Learnings from CAI](./LEARNINGS_FROM_CAI.md)** - 10 actionable insights
- **[Nexus vs Handoffs](./NEXUS_VS_HANDOFFS.md)** - Hybrid handoff strategy
- **[Comparison with CAI](./COMPARISON_WITH_CAI.md)** - Competitive analysis
- **[GitHub Issues Roadmap](./GITHUB_ISSUES_ROADMAP.md)** - Development roadmap (28 issues, 12 weeks)
- **[Documentation Index](./DOCUMENTATION_INDEX.md)** - Complete doc map

---

## 🗺️ Roadmap

### Phase 1: MVP (Weeks 1-12) ✅ In Progress

- [x] Repository setup
- [ ] Backend foundation (FastAPI, DB, auth)
- [ ] Frontend foundation (Next.js SaaS Starter)
- [ ] CAI enhancements (multi-model, guardrails, handoffs, HITL)
- [ ] ReconEngine (Subfinder, Nmap, HTTPx)
- [ ] AssessmentEngine (Nuclei, SQLMap)
- [ ] Docker sandboxing
- [ ] Kubernetes deployment

**Deliverables**: Working MVP with 5 security tools, multi-tenant SaaS, HITL approval

### Phase 2: Intelligence & Automation (Months 4-6)

- [ ] Diff detection UI
- [ ] Amass integration (deep OSINT)
- [ ] OSINT tools (theHarvester, SpiderFoot)
- [ ] Feedback loops (iterative refinement)
- [ ] Tracing/observability (LangSmith or Phoenix)
- [ ] Public benchmarks (performance transparency)

**Deliverables**: Historical context, trend analysis, advanced OSINT

### Phase 3: Enterprise Features (Months 7-12)

- [ ] Plugin architecture (custom tools)
- [ ] SSO integration (Okta, Azure AD)
- [ ] Compliance automation (OWASP, PCI-DSS reports)
- [ ] Multi-region deployment
- [ ] Firecracker microVMs (VM-level sandboxing)
- [ ] Research paper publication

**Deliverables**: Enterprise-ready platform, academic validation

**See**: [GITHUB_ISSUES_ROADMAP.md](./GITHUB_ISSUES_ROADMAP.md) for detailed 28-issue breakdown

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

**Current Focus** (MVP):
- Issue #9: LiteLLM integration
- Issue #10: Prompt injection guardrails
- Issue #11: Hybrid agent handoffs
- Issue #13-15: Recon agents (Subfinder, HTTPx, Nmap)

**How to Contribute**:
1. Check [GitHub Issues](https://github.com/windoliver/ThreatWeaver/issues)
2. Comment on issue to claim it
3. Fork repository
4. Create feature branch (`git checkout -b feature/amazing-feature`)
5. Commit changes (`git commit -m 'Add amazing feature'`)
6. Push to branch (`git push origin feature/amazing-feature`)
7. Open Pull Request

---

## 🔒 Security

**Responsible Disclosure**: If you discover a security vulnerability, please email security@threatweaver.com (do NOT open a public issue).

**Sandboxing**: All security tools run in isolated Docker containers with resource limits. See [architecture.md](./architecture.md#infrastructure--security-sandboxing) for details.

**Scope Validation**: DNS TXT verification required before scanning. Blocklists prevent scanning .gov, .mil, localhost, and cloud metadata endpoints.

**Legal**: ThreatWeaver is for **authorized security testing only**. Users must have explicit permission to scan targets. See [Terms of Service](./TERMS.md).

---

## 📊 Comparison with Similar Tools

### ThreatWeaver vs CAI (Alias Robotics)

| Aspect | ThreatWeaver | CAI |
|--------|--------------|-----|
| **Deployment** | Cloud SaaS (Kubernetes) | CLI tool (pip install) |
| **Users** | Teams, enterprises | Individual researchers |
| **Persistence** | PostgreSQL + S3 (permanent) | Ephemeral (no storage) |
| **Multi-Tenancy** | ✅ Teams, RBAC, billing | ❌ Single-user |
| **Continuous Monitoring** | ✅ Scheduled scans, alerts | ❌ One-off tests |
| **Cost** | $0-499/mo (subscription) | $0-100/mo (LLM APIs) |
| **Best For** | Production SaaS, compliance | Research, CTFs |

**Positioning**: ThreatWeaver is the **production evolution** of AI security automation—taking proven concepts from research tools like CAI and wrapping them with enterprise infrastructure.

**See**: [COMPARISON_WITH_CAI.md](./COMPARISON_WITH_CAI.md) for detailed analysis

---

## 💰 Pricing (Coming Soon)

**Free Tier**:
- 10 scans/month
- Basic tools (Subfinder, HTTPx, Nuclei)
- 7-day data retention
- Community support

**Pro ($99/month)**:
- 100 scans/month
- All tools (+ Nmap, SQLMap)
- 90-day data retention
- Email alerts
- Priority support

**Enterprise ($499/month)**:
- Unlimited scans
- Custom integrations
- 1-year data retention
- SSO (Phase 2)
- Dedicated account manager

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

**Inspired By**:
- **[CAI (Alias Robotics)](https://github.com/aliasrobotics/cai)**: Multi-model flexibility, guardrails, handoff patterns
- **[LangGraph DeepAgents](https://github.com/langchain-ai/deepagents)**: Hierarchical agent coordination
- **[Nexus](https://github.com/nexi-lab/nexus)**: Multi-agent workspace patterns
- **[Syntar](https://github.com/tafeng/syntar)**: Two-engine architecture reference
- **[Next.js SaaS Starter](https://github.com/nextjs/saas-starter)**: Production-ready frontend

**Key Insight**: Don't reinvent the wheel—learn from proven frameworks, adapt to your market, and differentiate on infrastructure.

---

## 📧 Contact

- **Website**: https://threatweaver.com (coming soon)
- **GitHub Issues**: https://github.com/windoliver/ThreatWeaver/issues
- **Email**: contact@threatweaver.com
- **Twitter**: [@ThreatWeaver](https://twitter.com/ThreatWeaver)

---

**Built with ❤️ by the ThreatWeaver Team**

**Status**: 🚧 Alpha (MVP in development - 12 weeks to launch)
