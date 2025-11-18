# LLM Abstraction Layer - Quick Reference

## Installation

```bash
# Dependencies already installed with uv sync
# Set environment variable
export OPENROUTER_API_KEY="your-key-here"
```

## Basic Usage

### Simple Completion

```python
from src.llm import create_llm_provider, Message, MessageRole

provider = create_llm_provider()
messages = [Message(role=MessageRole.USER, content="Hello!")]
response = provider.complete(messages)
print(response.content)
```

### Async Completion

```python
response = await provider.complete_async(messages)
```

### Streaming

```python
# Sync
for chunk in provider.stream(messages):
    print(chunk, end="")

# Async
async for chunk in provider.stream_async(messages):
    print(chunk, end="")
```

## Configuration

### Environment Variables

```bash
OPENROUTER_API_KEY=sk-or-v1-...
DEFAULT_LLM_MODEL=anthropic/claude-3.5-sonnet
DEFAULT_LLM_TEMPERATURE=0.7
DEFAULT_LLM_MAX_TOKENS=4096
```

### Custom Config

```python
provider = create_llm_provider(
    model="openai/gpt-4-turbo",
    temperature=0.9,
    max_tokens=8192
)
```

## Message Types

```python
# Simple text
Message(role=MessageRole.USER, content="Hello")

# System prompt
Message(role=MessageRole.SYSTEM, content="You are an expert")

# Assistant response
Message(role=MessageRole.ASSISTANT, content="I understand")

# Multimodal (with vision)
Message(
    role=MessageRole.USER,
    content=[
        TextContent(text="Describe this image"),
        ImageContent(image_url="https://...")
    ]
)
```

## Function Calling

```python
tools = [{
    "type": "function",
    "function": {
        "name": "search",
        "description": "Search for information",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string"}
            }
        }
    }
}]

response = provider.complete(messages, tools=tools)
if response.tool_calls:
    # Handle function call
    pass
```

## Response Format

```python
response.content           # str | None
response.tool_calls        # list[dict] | None
response.usage             # TokenUsage
response.usage.total_tokens  # int
response.model             # str
response.response_id       # str
```

## Error Handling

```python
from src.llm.exceptions import (
    LLMAuthenticationError,
    LLMRateLimitError,
    LLMTimeoutError,
)

try:
    response = provider.complete(messages)
except LLMAuthenticationError:
    # Invalid API key
    pass
except LLMRateLimitError:
    # Rate limit hit
    pass
except LLMTimeoutError:
    # Request timeout
    pass
```

## Popular Models

```python
# Anthropic Claude
"anthropic/claude-3.5-sonnet"    # Best for complex tasks
"anthropic/claude-3-opus"        # Most capable
"anthropic/claude-3-haiku"       # Fast & cheap

# OpenAI GPT
"openai/gpt-4-turbo"            # Latest GPT-4
"openai/gpt-4o"                 # Multimodal
"openai/gpt-3.5-turbo"          # Fast & affordable

# Google Gemini
"google/gemini-pro"             # Capable
"google/gemini-pro-vision"      # Vision support

# Meta Llama
"meta-llama/llama-3.1-405b"     # Largest
"meta-llama/llama-3.1-70b"      # Balanced
```

## Conversation Example

```python
messages = [
    Message(role=MessageRole.SYSTEM, content="You are helpful"),
    Message(role=MessageRole.USER, content="Hi"),
]

response = provider.complete(messages)

# Continue conversation
messages.append(Message(role=MessageRole.ASSISTANT, content=response.content))
messages.append(Message(role=MessageRole.USER, content="Tell me more"))

response = provider.complete(messages)
```

## Testing

```bash
# Run tests
pytest tests/test_llm.py -v

# With coverage
pytest tests/test_llm.py --cov=src/llm

# Integration tests (requires API key)
pytest tests/test_llm.py -v -m integration
```

## Common Patterns

### With Context Manager

```python
async def use_llm():
    provider = create_llm_provider()
    try:
        response = await provider.complete_async(messages)
        return response
    finally:
        await provider.cleanup()
```

### With Retry Override

```python
from src.llm import create_llm_config, OpenRouterProvider

config = create_llm_config(
    num_retries=5,
    retry_min_wait=2.0,
    retry_max_wait=30.0
)
provider = OpenRouterProvider(config)
```

### Different Temperatures

```python
# More creative
creative = create_llm_provider(temperature=1.0)

# More focused
focused = create_llm_provider(temperature=0.3)

# Deterministic (as much as possible)
deterministic = create_llm_provider(temperature=0.0)
```

## Full Documentation

See [LLM_ABSTRACTION.md](LLM_ABSTRACTION.md) for complete documentation.

## Examples

See `examples/llm_basic_usage.py` for runnable examples.
