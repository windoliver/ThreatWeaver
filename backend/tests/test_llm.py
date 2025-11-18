"""Tests for LLM abstraction layer."""

import pytest
from pydantic import SecretStr

from src.llm import (
    LLMConfig,
    Message,
    MessageRole,
    OpenRouterProvider,
    TextContent,
    create_llm_config,
    create_llm_provider,
)
from src.llm.exceptions import LLMAuthenticationError, LLMInvalidRequestError


class TestLLMConfig:
    """Tests for LLMConfig."""

    def test_default_config(self):
        """Test default configuration."""
        config = LLMConfig(model="anthropic/claude-3.5-sonnet")
        assert config.model == "anthropic/claude-3.5-sonnet"
        assert config.base_url == "https://openrouter.ai/api/v1"
        assert config.temperature == 0.7
        assert config.max_tokens == 4096
        assert config.supports_function_calling is True

    def test_custom_config(self):
        """Test custom configuration."""
        config = LLMConfig(
            model="openai/gpt-4",
            api_key=SecretStr("test-key"),
            temperature=0.9,
            max_tokens=8192,
            site_name="TestApp",
        )
        assert config.model == "openai/gpt-4"
        assert config.api_key.get_secret_value() == "test-key"
        assert config.temperature == 0.9
        assert config.max_tokens == 8192
        assert config.site_name == "TestApp"


class TestMessage:
    """Tests for Message class."""

    def test_simple_message(self):
        """Test simple text message."""
        msg = Message(role=MessageRole.USER, content="Hello, world!")
        msg_dict = msg.model_dump()
        assert msg_dict["role"] == "user"
        assert msg_dict["content"] == "Hello, world!"

    def test_message_with_text_content(self):
        """Test message with structured text content."""
        msg = Message(
            role=MessageRole.USER,
            content=[TextContent(text="Hello"), TextContent(text=" world")],
        )
        msg.vision_enabled = False
        msg_dict = msg.model_dump()
        assert msg_dict["role"] == "user"
        assert msg_dict["content"] == "Hello world"

    def test_message_from_dict(self):
        """Test creating message from dict."""
        data = {
            "role": "assistant",
            "content": "Hello!",
        }
        msg = Message.from_dict(data)
        assert msg.role == MessageRole.ASSISTANT
        assert msg.content == "Hello!"


class TestFactory:
    """Tests for factory functions."""

    def test_create_llm_config(self):
        """Test creating config with factory."""
        config = create_llm_config(model="openai/gpt-4", temperature=0.5)
        assert config.model == "openai/gpt-4"
        assert config.temperature == 0.5

    def test_create_llm_provider(self):
        """Test creating provider with factory."""
        provider = create_llm_provider(model="anthropic/claude-3.5-sonnet")
        assert isinstance(provider, OpenRouterProvider)
        assert provider.config.model == "anthropic/claude-3.5-sonnet"


class TestOpenRouterProvider:
    """Tests for OpenRouterProvider."""

    def test_provider_initialization(self):
        """Test provider initialization."""
        config = LLMConfig(
            model="anthropic/claude-3.5-sonnet",
            api_key=SecretStr("test-key"),
        )
        provider = OpenRouterProvider(config)
        assert provider.config.model == "anthropic/claude-3.5-sonnet"
        assert hasattr(provider, "client")
        assert hasattr(provider, "async_client")

    def test_format_messages(self):
        """Test message formatting."""
        config = LLMConfig(model="anthropic/claude-3.5-sonnet")
        provider = OpenRouterProvider(config)

        messages = [
            Message(role=MessageRole.SYSTEM, content="You are a helpful assistant."),
            Message(role=MessageRole.USER, content="Hello!"),
        ]

        formatted = provider._format_messages(messages)
        assert len(formatted) == 2
        assert formatted[0]["role"] == "system"
        assert formatted[0]["content"] == "You are a helpful assistant."
        assert formatted[1]["role"] == "user"
        assert formatted[1]["content"] == "Hello!"

    @pytest.mark.asyncio
    async def test_cleanup(self):
        """Test async cleanup."""
        config = LLMConfig(
            model="anthropic/claude-3.5-sonnet",
            api_key=SecretStr("test-key"),
        )
        provider = OpenRouterProvider(config)
        await provider.cleanup()


# Integration tests (require API key)
@pytest.mark.integration
@pytest.mark.skipif(
    True,  # Skip by default - only run with real API key
    reason="Integration test requires OpenRouter API key",
)
class TestOpenRouterIntegration:
    """Integration tests for OpenRouter (requires real API key)."""

    @pytest.mark.asyncio
    async def test_complete_async(self):
        """Test async completion."""
        provider = create_llm_provider()
        messages = [
            Message(role=MessageRole.USER, content="Say 'Hello, ThreatWeaver!' and nothing else."),
        ]

        response = await provider.complete_async(messages)
        assert response.content is not None
        assert "ThreatWeaver" in response.content
        assert response.usage.total_tokens > 0

    def test_complete_sync(self):
        """Test sync completion."""
        provider = create_llm_provider()
        messages = [
            Message(role=MessageRole.USER, content="Say 'Hello, ThreatWeaver!' and nothing else."),
        ]

        response = provider.complete(messages)
        assert response.content is not None
        assert "ThreatWeaver" in response.content
        assert response.usage.total_tokens > 0
