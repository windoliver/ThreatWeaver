# ThreatWeaver Infrastructure

Infrastructure as Code for ThreatWeaver deployment.

## Structure

```
infrastructure/
├── docker/               # Docker configurations
│   ├── docker-compose.yml
│   ├── backend.Dockerfile
│   ├── frontend.Dockerfile
│   └── tools/            # Security tool Docker images
│       ├── nmap.Dockerfile
│       ├── nuclei.Dockerfile
│       ├── subfinder.Dockerfile
│       ├── httpx.Dockerfile
│       └── sqlmap.Dockerfile
├── kubernetes/           # Kubernetes manifests
│   ├── helm/             # Helm chart
│   ├── base/             # Base manifests
│   └── overlays/         # Kustomize overlays (dev, staging, prod)
├── terraform/            # Terraform for cloud resources (GCP, AWS)
└── .env.example          # Environment variables template
```

## Getting Started

### Local Development (Docker Compose)

See [Issue #2](https://github.com/windoliver/ThreatWeaver/issues/2) for Docker setup.

### Production Deployment (Kubernetes)

See [Issue #25](https://github.com/windoliver/ThreatWeaver/issues/25) for Kubernetes setup.

## Components

- **Backend**: FastAPI application (3 replicas)
- **Frontend**: Next.js application (2 replicas)
- **Celery Workers**: Task processing (5 replicas)
- **PostgreSQL**: Primary database (1 primary + 2 read replicas)
- **Redis**: Task queue and caching (3-node cluster)
- **MinIO/S3**: Object storage (Nexus workspace)

## Documentation

- [Deployment Guide](../docs/DEPLOYMENT.md) - Coming soon (Issue #26)
- [Architecture](../architecture.md) - Section 10 (Deployment Architecture)
