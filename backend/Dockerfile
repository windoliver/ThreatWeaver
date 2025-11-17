# Backend Dockerfile for ThreatWeaver
# Multi-stage build for smaller production images

FROM python:3.11-slim as base

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    gcc \
    g++ \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install uv (fast Python package manager)
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.cargo/bin:$PATH"

# Development stage
FROM base as development

# Copy dependency files
COPY pyproject.toml ./
# COPY uv.lock ./  # Uncomment when uv.lock exists

# Install dependencies (development)
RUN uv pip install --system --no-cache \
    fastapi \
    uvicorn[standard] \
    sqlalchemy \
    alembic \
    psycopg2-binary \
    redis \
    celery \
    boto3 \
    python-jose[cryptography] \
    passlib[bcrypt] \
    python-multipart \
    pydantic \
    pydantic-settings \
    structlog \
    # LangChain & LLM
    langchain \
    langchain-openai \
    langchain-anthropic \
    langgraph \
    litellm \
    # Testing & Linting (dev only)
    pytest \
    pytest-cov \
    pytest-asyncio \
    httpx \
    ruff \
    black \
    mypy \
    bandit

# Copy application code
COPY . .

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Development command (will be overridden by docker-compose)
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# Production stage
FROM base as production

# Copy dependency files
COPY pyproject.toml ./

# Install dependencies (production only - no dev tools)
RUN uv pip install --system --no-cache \
    fastapi \
    uvicorn[standard] \
    sqlalchemy \
    alembic \
    psycopg2-binary \
    redis \
    celery \
    boto3 \
    python-jose[cryptography] \
    passlib[bcrypt] \
    python-multipart \
    pydantic \
    pydantic-settings \
    structlog \
    langchain \
    langchain-openai \
    langchain-anthropic \
    langgraph \
    litellm

# Copy only application code (not tests, docs, etc.)
COPY src/ ./src/

# Create non-root user
RUN useradd -m -u 1000 threatweaver && \
    chown -R threatweaver:threatweaver /app

USER threatweaver

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Production command
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
