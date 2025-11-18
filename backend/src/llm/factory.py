"""Factory for creating LLM providers."""

from pydantic import SecretStr

from src.config.settings import settings
from src.llm.config import LLMConfig
from src.llm.provider import LLMProvider, OpenRouterProvider


def create_llm_provider(
    model: str | None = None,
    api_key: str | None = None,
    temperature: float | None = None,
    max_tokens: int | None = None,
    **kwargs,
) -> LLMProvider:
    """Create an LLM provider with default settings from config.

    Args:
        model: Model name (defaults to settings.default_llm_model)
        api_key: API key (defaults to settings.openrouter_api_key)
        temperature: Temperature (defaults to settings.default_llm_temperature)
        max_tokens: Max tokens (defaults to settings.default_llm_max_tokens)
        **kwargs: Additional configuration parameters

    Returns:
        Configured LLMProvider instance

    Example:
        >>> provider = create_llm_provider()
        >>> provider = create_llm_provider(model="anthropic/claude-3-opus")
        >>> provider = create_llm_provider(temperature=0.9, max_tokens=8192)
    """
    config = LLMConfig(
        model=model or settings.default_llm_model,
        api_key=SecretStr(api_key or settings.openrouter_api_key) if (api_key or settings.openrouter_api_key) else None,
        base_url=kwargs.get("base_url", settings.openrouter_base_url),
        temperature=temperature if temperature is not None else settings.default_llm_temperature,
        max_tokens=max_tokens if max_tokens is not None else settings.default_llm_max_tokens,
        site_url=kwargs.get("site_url", settings.openrouter_site_url),
        site_name=kwargs.get("site_name", settings.openrouter_site_name),
        # Optional overrides
        top_p=kwargs.get("top_p", 1.0),
        timeout=kwargs.get("timeout", 120.0),
        num_retries=kwargs.get("num_retries", 3),
        supports_vision=kwargs.get("supports_vision", False),
        supports_function_calling=kwargs.get("supports_function_calling", True),
    )

    return OpenRouterProvider(config)


def create_llm_config(
    model: str | None = None,
    api_key: str | None = None,
    temperature: float | None = None,
    max_tokens: int | None = None,
    **kwargs,
) -> LLMConfig:
    """Create an LLM configuration with default settings.

    Args:
        model: Model name (defaults to settings.default_llm_model)
        api_key: API key (defaults to settings.openrouter_api_key)
        temperature: Temperature (defaults to settings.default_llm_temperature)
        max_tokens: Max tokens (defaults to settings.default_llm_max_tokens)
        **kwargs: Additional configuration parameters

    Returns:
        LLMConfig instance

    Example:
        >>> config = create_llm_config()
        >>> config = create_llm_config(model="anthropic/claude-3-opus")
        >>> provider = OpenRouterProvider(config)
    """
    return LLMConfig(
        model=model or settings.default_llm_model,
        api_key=SecretStr(api_key or settings.openrouter_api_key) if (api_key or settings.openrouter_api_key) else None,
        base_url=kwargs.get("base_url", settings.openrouter_base_url),
        temperature=temperature if temperature is not None else settings.default_llm_temperature,
        max_tokens=max_tokens if max_tokens is not None else settings.default_llm_max_tokens,
        site_url=kwargs.get("site_url", settings.openrouter_site_url),
        site_name=kwargs.get("site_name", settings.openrouter_site_name),
        # Optional overrides
        top_p=kwargs.get("top_p", 1.0),
        timeout=kwargs.get("timeout", 120.0),
        num_retries=kwargs.get("num_retries", 3),
        supports_vision=kwargs.get("supports_vision", False),
        supports_function_calling=kwargs.get("supports_function_calling", True),
    )
