# ThreatWeaver Backend

FastAPI backend for the ThreatWeaver Multi-Agent Cybersecurity Platform.

## Features

- FastAPI web framework with automatic API documentation
- Structured logging with structlog (JSON in production, pretty console in dev)
- CORS middleware configured
- Pydantic settings management with environment variables
- uv package manager for fast dependency installation
- Type hints and validation throughout

## Project Structure

```
backend/
├── src/
│   ├── main.py              # FastAPI application entry point
│   ├── api/                 # API routes and endpoints
│   ├── agents/              # Agent implementations
│   ├── config/              # Configuration and settings
│   │   ├── settings.py      # Application settings
│   │   └── logging.py       # Logging configuration
│   ├── db/                  # Database models and connections
│   ├── llm/                 # LLM abstraction layer (OpenRouter)
│   ├── security/            # Authentication and security
│   └── storage/             # Storage backends for artifacts
├── tests/                   # Test files
├── examples/                # Example scripts
├── docs/                    # Backend documentation
├── pyproject.toml           # Project dependencies
└── .env.example             # Example environment variables
```

## Quick Start

### Prerequisites

- Python 3.11+
- uv package manager

### Installation

1. Install dependencies:
```bash
uv sync
```

2. Copy the example environment file:
```bash
cp .env.example .env
```

3. Edit `.env` and configure your settings (API keys, database URL, etc.)

### Running the Server

Development mode (with auto-reload):
```bash
uv run uvicorn src.main:app --reload --host 0.0.0.0 --port 8000
```

Or activate the virtual environment:
```bash
source .venv/bin/activate
python -m uvicorn src.main:app --reload --host 0.0.0.0 --port 8000
```

The server will start at http://localhost:8000

### API Documentation

Once the server is running, you can access:

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc
- OpenAPI JSON: http://localhost:8000/openapi.json

### Health Check

```bash
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "healthy",
  "app": "ThreatWeaver",
  "version": "0.1.0",
  "environment": "development"
}
```

## Development

### Code Quality

Format and lint code:
```bash
uv run ruff check src/
uv run ruff format src/
```

Type checking:
```bash
uv run mypy src/
```

### Testing

Run tests:
```bash
uv run pytest
```

With coverage:
```bash
uv run pytest --cov=src --cov-report=html
```

## Configuration

All configuration is managed through environment variables and the `src/config/settings.py` file.

Key settings:
- `APP_NAME`: Application name
- `ENVIRONMENT`: development/staging/production
- `DEBUG`: Enable debug mode
- `LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR)
- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `OPENROUTER_API_KEY`: OpenRouter API key for LLM access
- `DEFAULT_LLM_MODEL`: Default model (e.g., anthropic/claude-3.5-sonnet)

See `.env.example` for all available options.

## LLM Abstraction Layer

ThreatWeaver includes a comprehensive LLM abstraction layer using OpenRouter for access to 300+ AI models.

**Quick Example:**

```python
from src.llm import create_llm_provider, Message, MessageRole

# Create provider with defaults
provider = create_llm_provider()

# Send message
messages = [Message(role=MessageRole.USER, content="Explain SQL injection")]
response = provider.complete(messages)
print(response.content)
```

**Features:**
- Multi-model support via OpenRouter (Claude, GPT-4, Gemini, Llama, etc.)
- Sync and async interfaces
- Streaming responses
- Function/tool calling
- Vision support
- Automatic retries
- Comprehensive error handling

**Documentation:** See [LLM Abstraction Layer](docs/LLM_ABSTRACTION.md) for full documentation.

**Examples:** Check `examples/llm_basic_usage.py` for complete examples.

## Logging

The application uses structured logging via structlog:
- Development: Pretty colored console output
- Production: JSON-formatted logs for parsing

Example log entry:
```python
from src.config.logging import get_logger

logger = get_logger(__name__)
logger.info("processing_request", user_id=123, action="scan")
```

## Docker

The backend can be run in Docker using the compose setup in the project root:

```bash
# From project root
docker compose up backend
```

## Related Documentation

- [Architecture](../architecture.md) - System design
- [LLM Abstraction Layer](docs/LLM_ABSTRACTION.md) - LLM integration guide
- [Issue #4](https://github.com/windoliver/ThreatWeaver/issues/4) - Backend setup tracker
- [Issue #9](https://github.com/windoliver/ThreatWeaver/issues/9) - LLM abstraction layer implementation

## License

See main project LICENSE file.
