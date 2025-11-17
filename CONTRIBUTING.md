# Contributing to ThreatWeaver

Thank you for your interest in contributing to ThreatWeaver! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct:

- Be respectful and inclusive
- Welcome newcomers and help them get started
- Focus on what is best for the community
- Show empathy towards other community members

## Getting Started

### Prerequisites

- Docker & Docker Compose
- Python 3.11+ (for backend development)
- Node.js 18+ (for frontend development)
- Git

### Local Setup

1. **Fork the repository**

```bash
# Fork via GitHub UI, then clone your fork
git clone https://github.com/YOUR_USERNAME/ThreatWeaver.git
cd ThreatWeaver
```

2. **Add upstream remote**

```bash
git remote add upstream https://github.com/windoliver/ThreatWeaver.git
```

3. **Start development environment**

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your API keys (see docs/SETUP.md)

# Start all services
docker-compose up -d
```

4. **Verify setup**

```bash
# Backend should be running
curl http://localhost:8000/health

# Frontend should be running
open http://localhost:3000
```

## Development Workflow

### 1. Find an Issue

- Check [GitHub Issues](https://github.com/windoliver/ThreatWeaver/issues)
- Look for issues labeled `good-first-issue` or `help-wanted`
- Comment "I'll take this" to claim the issue

### 2. Create a Branch

```bash
# Update your main branch
git checkout main
git pull upstream main

# Create feature branch
git checkout -b feature/issue-123-short-description
```

**Branch naming convention**:
- `feature/issue-123-description` - New features
- `fix/issue-123-description` - Bug fixes
- `docs/issue-123-description` - Documentation only
- `refactor/issue-123-description` - Code refactoring

### 3. Make Changes

- Follow the issue's acceptance criteria
- Write tests for new functionality
- Update documentation as needed
- Follow coding standards (see below)

### 4. Test Your Changes

**Backend (Python)**:
```bash
cd backend

# Run linter
ruff check .
black --check .
mypy .

# Run tests
pytest --cov --cov-report=html

# Security scan
bandit -r src/
```

**Frontend (TypeScript)**:
```bash
cd frontend

# Run linter
npm run lint

# Type check
npm run type-check

# Run tests
npm run test
```

### 5. Commit Changes

Use [Conventional Commits](https://www.conventionalcommits.org/) format:

```bash
git add .

# Format: <type>(<scope>): <subject>
git commit -m "feat(agents): add Subfinder integration

- Implement SubdomainDiscoveryAgent class
- Add Subfinder CLI wrapper
- Write results to Nexus workspace

Closes #13"
```

**Commit types**:
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation only
- `refactor:` - Code refactoring
- `test:` - Adding tests
- `chore:` - Build, CI, dependencies

### 6. Push and Create PR

```bash
# Push to your fork
git push origin feature/issue-123-short-description

# Create PR via GitHub CLI
gh pr create \
  --title "feat(agents): Add Subfinder integration" \
  --body "Closes #13

## Summary
Implements subdomain discovery agent using Subfinder.

## Changes
- Created SubdomainDiscoveryAgent class
- Added Subfinder CLI integration
- Added Celery task wrapper
- Added unit and integration tests

## Testing
- [x] Unit tests pass (100% coverage)
- [x] Integration test with real domain
- [x] Linter passes
- [x] Type checks pass

## Screenshots
(if applicable)"
```

## Pull Request Process

### PR Requirements

Before submitting a PR, ensure:

- [ ] All tests pass
- [ ] Code coverage >80%
- [ ] Linter passes (no warnings)
- [ ] Type checks pass
- [ ] Documentation updated
- [ ] CHANGELOG.md updated (for significant changes)
- [ ] Commit messages follow conventional commits
- [ ] PR description includes issue reference

### Review Process

1. **Automated checks** - CI must pass (GitHub Actions)
2. **Code review** - At least 1 approval required
3. **Testing** - Reviewer verifies functionality
4. **Merge** - Squash and merge to main
5. **Cleanup** - Delete feature branch

### PR Template

When you create a PR, include:

```markdown
## Closes
Closes #123

## Summary
Brief description of changes

## Changes
- Bullet list of changes

## Testing
- [x] Unit tests
- [x] Integration tests
- [x] Manual testing

## Screenshots
(if UI changes)
```

## Coding Standards

### Python (Backend)

**Style**:
- Follow [PEP 8](https://pep8.org/)
- Use [Black](https://black.readthedocs.io/) for formatting
- Use [Ruff](https://beta.ruff.rs/) for linting
- Use [mypy](http://mypy-lang.org/) for type checking

**Example**:
```python
from typing import List, Optional
from pydantic import BaseModel

class SubdomainResult(BaseModel):
    """Subdomain discovery result."""

    domain: str
    subdomains: List[str]
    timestamp: str

    def count(self) -> int:
        """Return number of subdomains found."""
        return len(self.subdomains)
```

**Best practices**:
- Use type hints for all functions
- Write docstrings (Google style)
- Use Pydantic models for data validation
- Use async/await for I/O operations
- Log using structlog

### TypeScript (Frontend)

**Style**:
- Follow [Airbnb TypeScript Style Guide](https://github.com/airbnb/javascript)
- Use [ESLint](https://eslint.org/) for linting
- Use [Prettier](https://prettier.io/) for formatting

**Example**:
```typescript
interface Finding {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
}

export function FindingCard({ finding }: { finding: Finding }) {
  const severityColor = getSeverityColor(finding.severity);

  return (
    <Card>
      <Badge color={severityColor}>{finding.severity}</Badge>
      <h3>{finding.title}</h3>
      <p>{finding.description}</p>
    </Card>
  );
}
```

**Best practices**:
- Use functional components with hooks
- Use TypeScript strict mode
- Use shadcn/ui components
- Use TanStack Query for data fetching
- Use Zustand for state management

## Testing

### Backend Tests

**Location**: `backend/tests/`

**Structure**:
```
backend/tests/
├── unit/          # Unit tests (fast, isolated)
├── integration/   # Integration tests (DB, agents)
└── e2e/           # End-to-end tests (full workflows)
```

**Example**:
```python
import pytest
from src.agents.subfinder import SubdomainDiscoveryAgent

@pytest.mark.asyncio
async def test_subfinder_discovers_subdomains():
    agent = SubdomainDiscoveryAgent()
    result = await agent.execute("example.com")

    assert result.domain == "example.com"
    assert len(result.subdomains) > 0
    assert "www.example.com" in result.subdomains
```

**Run tests**:
```bash
# All tests
pytest

# With coverage
pytest --cov --cov-report=html

# Specific test
pytest tests/unit/agents/test_subfinder.py::test_subfinder_discovers_subdomains

# Integration tests only
pytest tests/integration/
```

### Frontend Tests

**Location**: `frontend/__tests__/`

**Example**:
```typescript
import { render, screen } from '@testing-library/react';
import { FindingCard } from '@/components/FindingCard';

describe('FindingCard', () => {
  it('renders finding details', () => {
    const finding = {
      id: '1',
      severity: 'critical',
      title: 'SQL Injection',
      description: 'SQL injection vulnerability found',
    };

    render(<FindingCard finding={finding} />);

    expect(screen.getByText('SQL Injection')).toBeInTheDocument();
    expect(screen.getByText('critical')).toBeInTheDocument();
  });
});
```

**Run tests**:
```bash
# All tests
npm run test

# Watch mode
npm run test:watch

# Coverage
npm run test:coverage
```

## Documentation

### What to Document

- **New features** - Add to README.md and docs/
- **API changes** - Update docs/API_REFERENCE.md
- **Architecture changes** - Update architecture.md
- **Setup changes** - Update docs/SETUP.md

### Docstring Format (Python)

Use Google-style docstrings:

```python
def analyze_findings(findings: List[Finding], threshold: float) -> AnalysisResult:
    """Analyze vulnerability findings and prioritize by risk.

    Args:
        findings: List of vulnerability findings to analyze
        threshold: Risk threshold (0.0-1.0) for prioritization

    Returns:
        AnalysisResult containing prioritized findings and statistics

    Raises:
        ValueError: If threshold is not between 0.0 and 1.0

    Example:
        >>> findings = load_findings("scan_123")
        >>> result = analyze_findings(findings, threshold=0.7)
        >>> print(result.high_priority_count)
        42
    """
    if not 0.0 <= threshold <= 1.0:
        raise ValueError("Threshold must be between 0.0 and 1.0")

    # Implementation...
```

## Questions?

- **GitHub Issues**: https://github.com/windoliver/ThreatWeaver/issues
- **Discussions**: https://github.com/windoliver/ThreatWeaver/discussions
- **Email**: contact@threatweaver.com

## Recognition

Contributors will be recognized in:
- GitHub contributors page
- CHANGELOG.md for significant contributions
- README.md acknowledgments section

Thank you for contributing to ThreatWeaver! 🎉
