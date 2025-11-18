"""LLM configuration."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, SecretStr


class LLMConfig(BaseModel):
    """Configuration for an LLM provider."""

    model_config = ConfigDict(validate_assignment=True)

    # Model configuration
    model: str = Field(description="Model name (e.g., anthropic/claude-3.5-sonnet)")
    api_key: SecretStr | None = Field(default=None, description="API key for the provider")
    base_url: str = Field(
        default="https://openrouter.ai/api/v1", description="Base URL for the API endpoint"
    )

    # Generation parameters
    temperature: float = Field(default=0.7, ge=0.0, le=2.0, description="Sampling temperature")
    max_tokens: int = Field(default=4096, description="Maximum output tokens")
    top_p: float = Field(default=1.0, ge=0.0, le=1.0, description="Nucleus sampling parameter")

    # Timeout and retry
    timeout: float = Field(default=120.0, description="Timeout in seconds")
    num_retries: int = Field(default=3, ge=0, description="Number of retries on failure")
    retry_min_wait: float = Field(
        default=4.0, description="Minimum wait time between retries (seconds)"
    )
    retry_max_wait: float = Field(
        default=10.0, description="Maximum wait time between retries (seconds)"
    )
    retry_multiplier: float = Field(default=2.0, description="Exponential backoff multiplier")

    # Feature flags
    supports_vision: bool = Field(default=False, description="Whether model supports vision")
    supports_function_calling: bool = Field(
        default=True, description="Whether model supports function calling"
    )

    # OpenRouter specific
    site_url: str | None = Field(default=None, description="Your site URL for OpenRouter")
    site_name: str | None = Field(default=None, description="Your site name for OpenRouter")
