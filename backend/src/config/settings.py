"""Application settings and configuration."""

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "ThreatWeaver"
    app_version: str = "0.1.0"
    environment: Literal["development", "staging", "production"] = "development"
    debug: bool = Field(default=False)
    log_level: str = Field(default="INFO")

    # API
    api_v1_prefix: str = "/api/v1"
    cors_origins: list[str] = Field(default=["http://localhost:3000"])
    cors_allow_credentials: bool = True
    cors_allow_methods: list[str] = Field(default=["*"])
    cors_allow_headers: list[str] = Field(default=["*"])

    # Database
    database_url: str = Field(
        default="postgresql+asyncpg://postgres:postgres@localhost:5432/threatweaver"
    )
    database_echo: bool = False

    # Redis
    redis_url: str = Field(default="redis://localhost:6379/0")

    # Security
    secret_key: str = Field(default="dev-secret-key-change-in-production")
    access_token_expire_minutes: int = Field(default=30)

    # LLM
    openai_api_key: str = Field(default="")
    anthropic_api_key: str = Field(default="")
    litellm_model: str = Field(default="gpt-4")

    # Agent Configuration
    max_agent_iterations: int = Field(default=10)
    agent_timeout_seconds: int = Field(default=300)

    # Storage
    storage_backend: Literal["local", "s3"] = "local"
    local_storage_path: str = Field(default="./storage")
    s3_bucket_name: str = Field(default="")
    s3_region: str = Field(default="us-east-1")


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


# Global settings instance
settings = get_settings()
