"""LLM provider implementations."""

from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Iterator
from functools import wraps
from typing import Any

import httpx
from pydantic import BaseModel

from src.llm.config import LLMConfig
from src.llm.exceptions import (
    LLMAuthenticationError,
    LLMInvalidRequestError,
    LLMNoResponseError,
    LLMProviderError,
    LLMRateLimitError,
    LLMTimeoutError,
)
from src.llm.message import Message


class TokenUsage(BaseModel):
    """Token usage information."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class LLMResponse(BaseModel):
    """Response from an LLM completion."""

    content: str | None = None
    tool_calls: list[dict[str, Any]] | None = None
    usage: TokenUsage = TokenUsage()
    response_id: str = "unknown"
    model: str = "unknown"
    raw_response: dict[str, Any] = {}


def retry_decorator(
    num_retries: int = 3,
    retry_min_wait: float = 4.0,
    retry_max_wait: float = 10.0,
    retry_multiplier: float = 2.0,
) -> Any:
    """Decorator for retrying functions with exponential backoff."""

    def decorator(func: Any) -> Any:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            last_exception = None
            wait_time = retry_min_wait

            for attempt in range(num_retries + 1):
                try:
                    return func(*args, **kwargs)
                except (LLMRateLimitError, LLMTimeoutError, LLMNoResponseError) as e:
                    last_exception = e
                    if attempt < num_retries:
                        time.sleep(wait_time)
                        wait_time = min(wait_time * retry_multiplier, retry_max_wait)
                    else:
                        raise

            if last_exception:
                raise last_exception

        return wrapper

    return decorator


def async_retry_decorator(
    num_retries: int = 3,
    retry_min_wait: float = 4.0,
    retry_max_wait: float = 10.0,
    retry_multiplier: float = 2.0,
) -> Any:
    """Decorator for retrying async functions with exponential backoff."""

    def decorator(func: Any) -> Any:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            last_exception = None
            wait_time = retry_min_wait

            for attempt in range(num_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except (LLMRateLimitError, LLMTimeoutError, LLMNoResponseError) as e:
                    last_exception = e
                    if attempt < num_retries:
                        await asyncio.sleep(wait_time)
                        wait_time = min(wait_time * retry_multiplier, retry_max_wait)
                    else:
                        raise

            if last_exception:
                raise last_exception

        return wrapper

    return decorator


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    def __init__(self, config: LLMConfig):
        """Initialize the provider.

        Args:
            config: LLM configuration
        """
        self.config = config

    @abstractmethod
    def complete(
        self, messages: list[Message], tools: list[dict[str, Any]] | None = None, **kwargs: Any
    ) -> LLMResponse:
        """Send a completion request.

        Args:
            messages: List of messages
            tools: Optional list of tools for function calling
            **kwargs: Additional provider-specific parameters

        Returns:
            LLMResponse object
        """
        pass

    @abstractmethod
    async def complete_async(
        self, messages: list[Message], tools: list[dict[str, Any]] | None = None, **kwargs: Any
    ) -> LLMResponse:
        """Send an async completion request.

        Args:
            messages: List of messages
            tools: Optional list of tools for function calling
            **kwargs: Additional provider-specific parameters

        Returns:
            LLMResponse object
        """
        pass

    @abstractmethod
    def stream(
        self, messages: list[Message], tools: list[dict[str, Any]] | None = None, **kwargs: Any
    ) -> Iterator[str]:
        """Stream a completion response.

        Args:
            messages: List of messages
            tools: Optional list of tools for function calling
            **kwargs: Additional provider-specific parameters

        Yields:
            Response chunks as strings
        """
        pass

    @abstractmethod
    async def stream_async(
        self, messages: list[Message], tools: list[dict[str, Any]] | None = None, **kwargs: Any
    ) -> AsyncIterator[str]:
        """Stream an async completion response.

        Args:
            messages: List of messages
            tools: Optional list of tools for function calling
            **kwargs: Additional provider-specific parameters

        Yields:
            Response chunks as strings
        """
        pass

    @classmethod
    def from_config(cls, config: LLMConfig) -> LLMProvider:
        """Create a provider from config.

        Args:
            config: LLM configuration

        Returns:
            Appropriate LLM provider instance
        """
        return OpenRouterProvider(config)


class OpenRouterProvider(LLMProvider):
    """LLM provider using OpenRouter for multi-model support."""

    def __init__(self, config: LLMConfig):
        """Initialize the OpenRouter provider."""
        super().__init__(config)

        # Set up HTTP client
        headers = {
            "Authorization": f"Bearer {config.api_key.get_secret_value() if config.api_key else ''}",
            "Content-Type": "application/json",
        }

        # Add OpenRouter specific headers
        if config.site_url:
            headers["HTTP-Referer"] = config.site_url
        if config.site_name:
            headers["X-Title"] = config.site_name

        self.client = httpx.Client(
            base_url=config.base_url,
            headers=headers,
            timeout=config.timeout,
        )

        self.async_client = httpx.AsyncClient(
            base_url=config.base_url,
            headers=headers,
            timeout=config.timeout,
        )

    def _format_messages(self, messages: list[Message]) -> list[dict[str, Any]]:
        """Format messages for the provider."""
        # Set serialization flags
        for msg in messages:
            msg.vision_enabled = self.config.supports_vision
            msg.function_calling_enabled = self.config.supports_function_calling

        return [msg.model_dump() for msg in messages]

    def _handle_error(self, status_code: int, response_data: dict[str, Any]) -> None:
        """Handle HTTP error responses."""
        error_message = response_data.get("error", {}).get("message", str(response_data))

        if status_code == 401:
            raise LLMAuthenticationError(f"Authentication failed: {error_message}")
        elif status_code == 400:
            raise LLMInvalidRequestError(f"Invalid request: {error_message}")
        elif status_code == 429:
            raise LLMRateLimitError(f"Rate limit exceeded: {error_message}")
        elif status_code >= 500:
            raise LLMProviderError(f"Provider error: {error_message}")
        else:
            raise LLMProviderError(f"HTTP {status_code}: {error_message}")

    @retry_decorator(num_retries=3)
    def complete(
        self, messages: list[Message], tools: list[dict[str, Any]] | None = None, **kwargs: Any
    ) -> LLMResponse:
        """Send a completion request."""
        formatted_messages = self._format_messages(messages)

        # Build request payload
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": formatted_messages,
            "temperature": kwargs.get("temperature", self.config.temperature),
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            "top_p": kwargs.get("top_p", self.config.top_p),
        }

        # Add tools if provided
        if tools and self.config.supports_function_calling:
            payload["tools"] = tools
            payload["tool_choice"] = kwargs.get("tool_choice", "auto")

        try:
            response = self.client.post("/chat/completions", json=payload)
            response_data = response.json()

            if response.status_code != 200:
                self._handle_error(response.status_code, response_data)

            # Parse response
            if not response_data.get("choices"):
                raise LLMNoResponseError("No choices in response")

            choice = response_data["choices"][0]
            message = choice.get("message", {})

            # Extract content and tool calls
            content = message.get("content")
            tool_calls = message.get("tool_calls")

            # Extract usage
            usage_data = response_data.get("usage", {})
            usage = TokenUsage(
                prompt_tokens=usage_data.get("prompt_tokens", 0),
                completion_tokens=usage_data.get("completion_tokens", 0),
                total_tokens=usage_data.get("total_tokens", 0),
            )

            return LLMResponse(
                content=content,
                tool_calls=tool_calls,
                usage=usage,
                response_id=response_data.get("id", "unknown"),
                model=response_data.get("model", self.config.model),
                raw_response=response_data,
            )

        except httpx.TimeoutException as e:
            raise LLMTimeoutError(f"Request timed out: {e}") from e
        except httpx.HTTPError as e:
            raise LLMProviderError(f"HTTP error: {e}") from e

    async def complete_async(
        self, messages: list[Message], tools: list[dict[str, Any]] | None = None, **kwargs: Any
    ) -> LLMResponse:
        """Send an async completion request."""
        formatted_messages = self._format_messages(messages)

        # Build request payload
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": formatted_messages,
            "temperature": kwargs.get("temperature", self.config.temperature),
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            "top_p": kwargs.get("top_p", self.config.top_p),
        }

        # Add tools if provided
        if tools and self.config.supports_function_calling:
            payload["tools"] = tools
            payload["tool_choice"] = kwargs.get("tool_choice", "auto")

        @async_retry_decorator(
            num_retries=self.config.num_retries,
            retry_min_wait=self.config.retry_min_wait,
            retry_max_wait=self.config.retry_max_wait,
            retry_multiplier=self.config.retry_multiplier,
        )
        async def _make_request() -> LLMResponse:
            try:
                response = await self.async_client.post("/chat/completions", json=payload)
                response_data = response.json()

                if response.status_code != 200:
                    self._handle_error(response.status_code, response_data)

                # Parse response
                if not response_data.get("choices"):
                    raise LLMNoResponseError("No choices in response")

                choice = response_data["choices"][0]
                message = choice.get("message", {})

                # Extract content and tool calls
                content = message.get("content")
                tool_calls = message.get("tool_calls")

                # Extract usage
                usage_data = response_data.get("usage", {})
                usage = TokenUsage(
                    prompt_tokens=usage_data.get("prompt_tokens", 0),
                    completion_tokens=usage_data.get("completion_tokens", 0),
                    total_tokens=usage_data.get("total_tokens", 0),
                )

                return LLMResponse(
                    content=content,
                    tool_calls=tool_calls,
                    usage=usage,
                    response_id=response_data.get("id", "unknown"),
                    model=response_data.get("model", self.config.model),
                    raw_response=response_data,
                )

            except httpx.TimeoutException as e:
                raise LLMTimeoutError(f"Request timed out: {e}") from e
            except httpx.HTTPError as e:
                raise LLMProviderError(f"HTTP error: {e}") from e

        return await _make_request()

    def stream(
        self, messages: list[Message], tools: list[dict[str, Any]] | None = None, **kwargs: Any
    ) -> Iterator[str]:
        """Stream a completion response."""
        formatted_messages = self._format_messages(messages)

        # Build request payload
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": formatted_messages,
            "temperature": kwargs.get("temperature", self.config.temperature),
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            "top_p": kwargs.get("top_p", self.config.top_p),
            "stream": True,
        }

        # Add tools if provided
        if tools and self.config.supports_function_calling:
            payload["tools"] = tools

        try:
            with self.client.stream("POST", "/chat/completions", json=payload) as response:
                if response.status_code != 200:
                    response_data = response.json()
                    self._handle_error(response.status_code, response_data)

                for line in response.iter_lines():
                    if line.startswith("data: "):
                        data = line[6:]
                        if data == "[DONE]":
                            break

                        import json

                        try:
                            chunk = json.loads(data)
                            if chunk.get("choices"):
                                delta = chunk["choices"][0].get("delta", {})
                                if "content" in delta and delta["content"]:
                                    yield delta["content"]
                        except json.JSONDecodeError:
                            continue

        except httpx.TimeoutException as e:
            raise LLMTimeoutError(f"Request timed out: {e}") from e
        except httpx.HTTPError as e:
            raise LLMProviderError(f"HTTP error: {e}") from e

    async def stream_async(
        self, messages: list[Message], tools: list[dict[str, Any]] | None = None, **kwargs: Any
    ) -> AsyncIterator[str]:
        """Stream an async completion response."""
        formatted_messages = self._format_messages(messages)

        # Build request payload
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": formatted_messages,
            "temperature": kwargs.get("temperature", self.config.temperature),
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            "top_p": kwargs.get("top_p", self.config.top_p),
            "stream": True,
        }

        # Add tools if provided
        if tools and self.config.supports_function_calling:
            payload["tools"] = tools

        try:
            async with self.async_client.stream("POST", "/chat/completions", json=payload) as response:
                if response.status_code != 200:
                    response_data = await response.json()
                    self._handle_error(response.status_code, response_data)

                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]
                        if data == "[DONE]":
                            break

                        import json

                        try:
                            chunk = json.loads(data)
                            if chunk.get("choices"):
                                delta = chunk["choices"][0].get("delta", {})
                                if "content" in delta and delta["content"]:
                                    yield delta["content"]
                        except json.JSONDecodeError:
                            continue

        except httpx.TimeoutException as e:
            raise LLMTimeoutError(f"Request timed out: {e}") from e
        except httpx.HTTPError as e:
            raise LLMProviderError(f"HTTP error: {e}") from e

    def __del__(self) -> None:
        """Clean up HTTP clients."""
        if hasattr(self, "client"):
            self.client.close()

    async def cleanup(self) -> None:
        """Clean up async HTTP client."""
        if hasattr(self, "async_client"):
            await self.async_client.aclose()
