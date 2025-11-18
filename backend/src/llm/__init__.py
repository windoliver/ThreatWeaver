"""LLM provider abstraction layer for ThreatWeaver.

Provides a unified interface for multiple LLM providers with:
- Multi-provider support via OpenRouter
- Function/tool calling
- Token counting
- Cost tracking
- Error handling
- Async support
"""

from src.llm.config import LLMConfig
from src.llm.exceptions import (
    LLMAuthenticationError,
    LLMConfigError,
    LLMException,
    LLMInvalidRequestError,
    LLMNoResponseError,
    LLMProviderError,
    LLMRateLimitError,
    LLMTimeoutError,
)
from src.llm.factory import create_llm_config, create_llm_provider
from src.llm.message import (
    ImageContent,
    ImageDetail,
    Message,
    MessageRole,
    TextContent,
    ToolCall,
    ToolFunction,
)
from src.llm.provider import LLMProvider, LLMResponse, OpenRouterProvider

__all__ = [
    # Config
    "LLMConfig",
    # Factory
    "create_llm_provider",
    "create_llm_config",
    # Providers
    "LLMProvider",
    "OpenRouterProvider",
    "LLMResponse",
    # Messages
    "Message",
    "MessageRole",
    "TextContent",
    "ImageContent",
    "ImageDetail",
    "ToolCall",
    "ToolFunction",
    # Exceptions
    "LLMException",
    "LLMProviderError",
    "LLMRateLimitError",
    "LLMTimeoutError",
    "LLMAuthenticationError",
    "LLMInvalidRequestError",
    "LLMNoResponseError",
    "LLMConfigError",
]
