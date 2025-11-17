# ThreatWeaver Setup Guide

Complete guide for setting up ThreatWeaver locally for development.

## Prerequisites

Before you begin, ensure you have the following installed:

- **Docker**: v24.0+ ([Install Docker](https://docs.docker.com/get-docker/))
- **Docker Compose**: v2.20+ (included with Docker Desktop)
- **Git**: v2.30+ ([Install Git](https://git-scm.com/downloads))
- **Python**: 3.11+ (for backend development without Docker)
- **Node.js**: 18+ (for frontend development without Docker)

### Verify Prerequisites

```bash
docker --version
# Docker version 24.0.0 or higher

docker compose version
# Docker Compose version v2.20.0 or higher

git --version
# git version 2.30.0 or higher

python --version
# Python 3.11.0 or higher

node --version
# v18.0.0 or higher
```

## Quick Start (Recommended)

### 1. Clone Repository

```bash
git clone https://github.com/windoliver/ThreatWeaver.git
cd ThreatWeaver
```

### 2. Create Environment File

```bash
# Copy the example environment file
cp .env.example .env

# Edit the .env file with your API keys
vim .env  # or use your preferred editor
```

**Required API Keys** (for MVP):
- `OPENAI_API_KEY` - Get from [OpenAI Platform](https://platform.openai.com/api-keys)
- `ANTHROPIC_API_KEY` - Get from [Anthropic Console](https://console.anthropic.com/)

**Optional** (for full features):
- `STRIPE_SECRET_KEY` - Get from [Stripe Dashboard](https://dashboard.stripe.com/test/apikeys)
- `SLACK_WEBHOOK_URL` - For HITL approval notifications
- `SENDGRID_API_KEY` - For email notifications

### 3. Start All Services

```bash
# Start all services in detached mode
docker compose up -d

# View logs
docker compose logs -f

# View logs for specific service
docker compose logs -f backend
```

**Expected Output**:
```
✔ Network threatweaver_threatweaver  Created
✔ Volume threatweaver_postgres_data  Created
✔ Volume threatweaver_redis_data     Created
✔ Volume threatweaver_minio_data     Created
✔ Container threatweaver-postgres    Started
✔ Container threatweaver-redis       Started
✔ Container threatweaver-minio       Started
✔ Container threatweaver-backend     Started
✔ Container threatweaver-celery      Started
✔ Container threatweaver-frontend    Started
```

### 4. Verify Services

**Check service health**:
```bash
docker compose ps
```

You should see all services as "healthy":
```
NAME                    STATUS              PORTS
threatweaver-postgres   Up (healthy)        0.0.0.0:5432->5432/tcp
threatweaver-redis      Up (healthy)        0.0.0.0:6379->6379/tcp
threatweaver-minio      Up (healthy)        0.0.0.0:9000-9001->9000-9001/tcp
threatweaver-backend    Up (healthy)        0.0.0.0:8000->8000/tcp
threatweaver-celery     Up
threatweaver-frontend   Up                  0.0.0.0:3000->3000/tcp
```

**Access services**:
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
- **MinIO Console**: http://localhost:9001 (login: minio / changeme123)

### 5. Initialize Database

```bash
# Run database migrations (when backend is implemented)
docker compose exec backend alembic upgrade head

# Create initial admin user (when auth is implemented)
docker compose exec backend python -m src.cli create-admin \
  --email admin@example.com \
  --password admin123
```

### 6. Verify Setup

**Test backend health**:
```bash
curl http://localhost:8000/health
# Expected: {"status": "ok"}
```

**Test frontend**:
```bash
open http://localhost:3000
# Should show ThreatWeaver login page
```

## Development Workflow

### Backend Development (Python)

**Option 1: Docker (Recommended)**
```bash
# Code changes auto-reload with --reload flag in docker-compose.yml
docker compose logs -f backend

# Run tests
docker compose exec backend pytest

# Linting
docker compose exec backend ruff check .
docker compose exec backend black --check .
docker compose exec backend mypy .
```

**Option 2: Local Python**
```bash
cd backend

# Install dependencies
pip install uv
uv pip install -r pyproject.toml

# Run server
uvicorn src.main:app --reload

# Run tests
pytest
```

### Frontend Development (TypeScript)

**Option 1: Docker (Recommended)**
```bash
# Code changes auto-reload in development mode
docker compose logs -f frontend

# Run linter
docker compose exec frontend npm run lint

# Type check
docker compose exec frontend npm run type-check
```

**Option 2: Local Node.js**
```bash
cd frontend

# Install dependencies
npm install

# Run dev server
npm run dev

# Open browser
open http://localhost:3000
```

### Database Management

**Connect to PostgreSQL**:
```bash
# Using psql
docker compose exec postgres psql -U threatweaver -d threatweaver

# Or use GUI tool (DBeaver, pgAdmin, etc.)
# Host: localhost
# Port: 5432
# Database: threatweaver
# Username: threatweaver
# Password: changeme
```

**Create migration**:
```bash
docker compose exec backend alembic revision --autogenerate -m "Add new table"
```

**Run migrations**:
```bash
docker compose exec backend alembic upgrade head
```

**Rollback migration**:
```bash
docker compose exec backend alembic downgrade -1
```

### Redis (Task Queue)

**Monitor Redis**:
```bash
# Connect to Redis CLI
docker compose exec redis redis-cli

# View all keys
redis-cli> KEYS *

# Monitor real-time commands
redis-cli> MONITOR
```

### MinIO (S3 Storage)

**Access MinIO Console**:
- URL: http://localhost:9001
- Username: `minio`
- Password: `changeme123`

**Create bucket** (if not auto-created):
```bash
docker compose exec minio mc alias set local http://localhost:9000 minio changeme123
docker compose exec minio mc mb local/threatweaver-workspace
```

## Troubleshooting

### Service Won't Start

**Check logs**:
```bash
docker compose logs backend
docker compose logs frontend
```

**Rebuild containers**:
```bash
docker compose down
docker compose build --no-cache
docker compose up -d
```

### Port Already in Use

If ports are already in use, change them in `docker-compose.yml`:
```yaml
services:
  backend:
    ports:
      - "8001:8000"  # Changed from 8000
```

### Database Connection Error

**Reset database**:
```bash
docker compose down -v  # WARNING: Deletes all data!
docker compose up -d
```

### Out of Memory

**Increase Docker resources**:
- Docker Desktop → Settings → Resources
- Set Memory to at least 8GB
- Set CPUs to at least 4

### Permission Errors

**Fix volume permissions**:
```bash
# Linux/Mac
sudo chown -R $USER:$USER .

# Reset Docker volumes
docker compose down -v
docker compose up -d
```

## Useful Commands

### Docker Compose

```bash
# Start all services
docker compose up -d

# Stop all services (preserves data)
docker compose down

# Stop and remove volumes (deletes data)
docker compose down -v

# Restart specific service
docker compose restart backend

# View logs
docker compose logs -f

# Execute command in container
docker compose exec backend bash
docker compose exec frontend sh

# Rebuild and restart
docker compose up -d --build

# Scale Celery workers
docker compose up -d --scale celery-worker=5
```

### Database

```bash
# Backup database
docker compose exec postgres pg_dump -U threatweaver threatweaver > backup.sql

# Restore database
cat backup.sql | docker compose exec -T postgres psql -U threatweaver -d threatweaver

# Reset database
docker compose down
docker volume rm threatweaver_postgres_data
docker compose up -d
```

### Testing

```bash
# Backend tests
docker compose exec backend pytest --cov

# Frontend tests
docker compose exec frontend npm run test

# Integration tests
docker compose exec backend pytest tests/integration/

# E2E tests (Playwright)
docker compose exec frontend npm run test:e2e
```

## Next Steps

Once your development environment is running:

1. **Complete backend setup** (Issue #4)
   - Implement FastAPI structure
   - Add database models
   - Create authentication endpoints

2. **Complete frontend setup** (Issue #7)
   - Set up Next.js SaaS Starter
   - Configure NextAuth.js
   - Integrate Stripe

3. **Start building agents** (Issues #13-19)
   - ReconEngine agents
   - AssessmentEngine agents

## Additional Resources

- [Architecture Documentation](../architecture.md)
- [Contributing Guide](../CONTRIBUTING.md)
- [GitHub Issues](https://github.com/windoliver/ThreatWeaver/issues)
- [API Reference](./API_REFERENCE.md) (coming soon)
- [User Guide](./USER_GUIDE.md) (coming soon)

## Support

**Issues**: https://github.com/windoliver/ThreatWeaver/issues
**Email**: contact@threatweaver.com
**Discussions**: https://github.com/windoliver/ThreatWeaver/discussions
