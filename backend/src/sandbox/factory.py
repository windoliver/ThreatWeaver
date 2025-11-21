"""
Sandbox provider factory.

This module provides a factory function to create the appropriate
sandbox provider based on configuration.
"""

import logging

from src.sandbox.config import SandboxConfig
from src.sandbox.protocol import SandboxProvider
from src.sandbox.providers.e2b_provider import E2BSandboxProvider

logger = logging.getLogger(__name__)


def get_sandbox_provider(
    config: SandboxConfig = None,
) -> SandboxProvider:
    """
    Get the configured sandbox provider.

    Args:
        config: Sandbox configuration (loaded from env if not provided)

    Returns:
        SandboxProvider instance (E2B or Docker)

    Raises:
        ValueError: If provider is not recognized or missing required config

    Example:
        >>> provider = get_sandbox_provider()
        >>> config = get_subfinder_config("example.com", "/workspace/subs.txt")
        >>> result = await provider.execute(config, "/tmp/scan-123", "scan-123")
    """
    if config is None:
        config = SandboxConfig.from_env()

    logger.info(f"Creating {config.provider} sandbox provider")

    if config.provider == "e2b":
        if not config.e2b_api_key:
            raise ValueError(
                "E2B_API_KEY environment variable is required for E2B provider"
            )

        return E2BSandboxProvider(
            api_key=config.e2b_api_key,
            template_id=config.e2b_template_id
        )

    elif config.provider == "docker":
        # TODO: Implement Docker provider
        raise NotImplementedError(
            "Docker sandbox provider not yet implemented. Use provider='e2b'"
        )

    else:
        raise ValueError(
            f"Unknown sandbox provider: {config.provider}. "
            f"Available providers: e2b, docker"
        )
