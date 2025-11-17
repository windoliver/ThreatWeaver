# ThreatWeaver Backend

FastAPI-based backend for ThreatWeaver multi-agent cybersecurity platform.

## Structure

```
backend/
├── src/
│   ├── api/              # API routes
│   ├── agents/           # Agent implementations (Subfinder, Nmap, etc.)
│   ├── config/           # Configuration management
│   ├── db/               # Database models (SQLAlchemy)
│   ├── security/         # Auth, guardrails, HITL
│   └── storage/          # Nexus/S3 integration
├── tests/
│   ├── unit/             # Unit tests
│   ├── integration/      # Integration tests
│   └── e2e/              # End-to-end tests
├── pyproject.toml        # Dependencies (managed by uv)
└── Dockerfile
```

## Getting Started

See [Issue #4](https://github.com/windoliver/ThreatWeaver/issues/4) for backend setup.

## Documentation

- [Architecture](../architecture.md) - System design
- [API Reference](../docs/API_REFERENCE.md) - API documentation
- [Contributing](../CONTRIBUTING.md) - Development guidelines
