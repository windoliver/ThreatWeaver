# LLM Abstraction Layer

The ThreatWeaver LLM abstraction layer provides a unified interface for interacting with multiple Large Language Models through OpenRouter.

## Architecture

The abstraction layer consists of several key components:

- **Provider Interface**: Abstract base class defining the LLM provider API
- **OpenRouter Provider**: Concrete implementation using OpenRouter API
- **Message Types**: Structured message format for conversations
- **Configuration**: Flexible configuration system with defaults
- **Factory**: Convenient factory functions for creating providers
- **Exceptions**: Comprehensive error handling

## Quick Start

### Basic Usage

```python
from src.llm import create_llm_provider, Message, MessageRole

# Create a provider with default settings
provider = create_llm_provider()

# Create messages
messages = [
    Message(role=MessageRole.SYSTEM, content="You are a helpful assistant."),
    Message(role=MessageRole.USER, content="What is cybersecurity?"),
]

# Get completion
response = provider.complete(messages)
print(response.content)
print(f"Tokens used: {response.usage.total_tokens}")
```

### Async Usage

```python
import asyncio
from src.llm import create_llm_provider, Message, MessageRole

async def main():
    provider = create_llm_provider()

    messages = [
        Message(role=MessageRole.USER, content="Explain SQL injection"),
    ]

    # Async completion
    response = await provider.complete_async(messages)
    print(response.content)

asyncio.run(main())
```

### Streaming Responses

```python
from src.llm import create_llm_provider, Message, MessageRole

provider = create_llm_provider()
messages = [Message(role=MessageRole.USER, content="Tell me about XSS attacks")]

# Sync streaming
for chunk in provider.stream(messages):
    print(chunk, end="", flush=True)

# Async streaming
async def stream_example():
    async for chunk in provider.stream_async(messages):
        print(chunk, end="", flush=True)
```

## Configuration

### Environment Variables

Add these to your `.env` file:

```bash
# OpenRouter Configuration
OPENROUTER_API_KEY=your_api_key_here
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
OPENROUTER_SITE_URL=https://your-app.com
OPENROUTER_SITE_NAME=ThreatWeaver

# Default LLM Settings
DEFAULT_LLM_MODEL=anthropic/claude-3.5-sonnet
DEFAULT_LLM_TEMPERATURE=0.7
DEFAULT_LLM_MAX_TOKENS=4096
```

### Custom Configuration

```python
from src.llm import create_llm_provider

# Override defaults
provider = create_llm_provider(
    model="openai/gpt-4-turbo",
    temperature=0.9,
    max_tokens=8192,
)

# Or use a custom config
from src.llm import LLMConfig, OpenRouterProvider
from pydantic import SecretStr

config = LLMConfig(
    model="anthropic/claude-3-opus",
    api_key=SecretStr("your-api-key"),
    temperature=0.5,
    max_tokens=16384,
    supports_vision=True,
    supports_function_calling=True,
)

provider = OpenRouterProvider(config)
```

## Advanced Features

### Function/Tool Calling

```python
from src.llm import create_llm_provider, Message, MessageRole

provider = create_llm_provider(
    model="anthropic/claude-3.5-sonnet",
    supports_function_calling=True,
)

# Define tools
tools = [
    {
        "type": "function",
        "function": {
            "name": "scan_port",
            "description": "Scan a port on a target host",
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "Target host IP"},
                    "port": {"type": "integer", "description": "Port number"},
                },
                "required": ["host", "port"],
            },
        },
    }
]

messages = [
    Message(role=MessageRole.USER, content="Scan port 80 on 192.168.1.1"),
]

response = provider.complete(messages, tools=tools)

# Check if LLM wants to call a function
if response.tool_calls:
    for tool_call in response.tool_calls:
        print(f"Function: {tool_call['function']['name']}")
        print(f"Arguments: {tool_call['function']['arguments']}")
```

### Vision Support

```python
from src.llm import (
    create_llm_provider,
    Message,
    MessageRole,
    TextContent,
    ImageContent,
)

provider = create_llm_provider(
    model="openai/gpt-4-vision-preview",
    supports_vision=True,
)

messages = [
    Message(
        role=MessageRole.USER,
        content=[
            TextContent(text="What vulnerabilities do you see in this network diagram?"),
            ImageContent(image_url="https://example.com/network-diagram.png"),
        ],
    ),
]

response = provider.complete(messages)
```

### Error Handling

```python
from src.llm import create_llm_provider, Message, MessageRole
from src.llm.exceptions import (
    LLMAuthenticationError,
    LLMRateLimitError,
    LLMTimeoutError,
    LLMProviderError,
)

provider = create_llm_provider()
messages = [Message(role=MessageRole.USER, content="Hello")]

try:
    response = provider.complete(messages)
except LLMAuthenticationError:
    print("Invalid API key")
except LLMRateLimitError:
    print("Rate limit exceeded, please retry later")
except LLMTimeoutError:
    print("Request timed out")
except LLMProviderError as e:
    print(f"Provider error: {e}")
```

### Retry Configuration

```python
from src.llm import create_llm_config, OpenRouterProvider

config = create_llm_config(
    model="anthropic/claude-3.5-sonnet",
    num_retries=5,
    retry_min_wait=2.0,
    retry_max_wait=30.0,
    retry_multiplier=2.5,
)

provider = OpenRouterProvider(config)
```

## Available Models

OpenRouter provides access to 300+ models. Common choices:

### Anthropic Claude
- `anthropic/claude-3.5-sonnet` - Best for complex tasks
- `anthropic/claude-3-opus` - Most capable, slower
- `anthropic/claude-3-haiku` - Fast, cost-effective

### OpenAI GPT
- `openai/gpt-4-turbo` - Latest GPT-4 with large context
- `openai/gpt-4o` - Multimodal GPT-4
- `openai/gpt-3.5-turbo` - Fast and affordable

### Google Gemini
- `google/gemini-pro` - Google's capable model
- `google/gemini-pro-vision` - With vision support

### Meta Llama
- `meta-llama/llama-3.1-405b` - Largest open model
- `meta-llama/llama-3.1-70b` - Good balance

See [OpenRouter Models](https://openrouter.ai/models) for the full list.

## Response Format

All completions return an `LLMResponse` object:

```python
class LLMResponse:
    content: str | None           # Response text
    tool_calls: list[dict] | None # Function calls made
    usage: TokenUsage             # Token usage info
    response_id: str              # Unique response ID
    model: str                    # Model that generated response
    raw_response: dict            # Raw API response

class TokenUsage:
    prompt_tokens: int      # Input tokens
    completion_tokens: int  # Output tokens
    total_tokens: int       # Total tokens
```

## Testing

Run tests:

```bash
# Run unit tests
pytest tests/test_llm.py -v -k "not integration"

# Run with coverage
pytest tests/test_llm.py --cov=src/llm

# Run integration tests (requires API key)
pytest tests/test_llm.py -v -m integration
```

## API Reference

### Factory Functions

#### `create_llm_provider()`

Create a provider with default settings.

**Parameters:**
- `model` (str, optional): Model name
- `api_key` (str, optional): API key
- `temperature` (float, optional): Sampling temperature (0.0-2.0)
- `max_tokens` (int, optional): Maximum output tokens
- `**kwargs`: Additional config parameters

**Returns:** `LLMProvider`

#### `create_llm_config()`

Create a configuration object.

**Parameters:** Same as `create_llm_provider()`

**Returns:** `LLMConfig`

### Provider Methods

#### `complete(messages, tools=None, **kwargs)`

Synchronous completion request.

**Parameters:**
- `messages` (list[Message]): Conversation messages
- `tools` (list[dict], optional): Available tools/functions
- `**kwargs`: Additional parameters

**Returns:** `LLMResponse`

#### `complete_async(messages, tools=None, **kwargs)`

Async completion request.

**Parameters:** Same as `complete()`

**Returns:** `LLMResponse` (awaitable)

#### `stream(messages, tools=None, **kwargs)`

Synchronous streaming.

**Parameters:** Same as `complete()`

**Yields:** `str` chunks

#### `stream_async(messages, tools=None, **kwargs)`

Async streaming.

**Parameters:** Same as `complete()`

**Yields:** `str` chunks (async iterator)

## Best Practices

1. **Use factory functions** for simple cases
2. **Configure retry logic** for production use
3. **Handle exceptions** appropriately
4. **Monitor token usage** to control costs
5. **Use streaming** for better UX with long responses
6. **Choose appropriate models** based on task complexity
7. **Set timeouts** based on expected response time
8. **Clean up async resources** with `await provider.cleanup()`

## Examples

See the following for complete examples:

- `backend/tests/test_llm.py` - Unit tests with usage examples
- `backend/src/agents/` - Agent implementations using LLM layer

## Troubleshooting

### Common Issues

**Authentication Error:**
- Check `OPENROUTER_API_KEY` is set correctly
- Verify API key is valid at https://openrouter.ai/keys

**Rate Limit Error:**
- Increase retry settings
- Add delays between requests
- Consider upgrading OpenRouter plan

**Timeout Error:**
- Increase `timeout` parameter
- Use streaming for long responses
- Choose faster models

**Import Error:**
- Ensure you're importing from `src.llm`
- Check virtual environment is activated
- Verify dependencies installed with `uv sync`

## Future Enhancements

Planned improvements (see GitHub issues):

- Token counting utilities
- Cost tracking and budgets
- Response caching layer
- Multi-provider fallback
- Prompt templates
- Conversation history management
