"""
Application configuration using Pydantic Settings.
Loads from environment variables or .env file with validated fallbacks.
"""

from pathlib import Path
from typing import List
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    ENV: str = Field(default="development", description="Environment: development, test, production")
    DEBUG: bool = Field(default=False, description="Debug mode flag")
    HOST: str = Field(default="127.0.0.1", description="API server host")
    PORT: int = Field(default=8000, description="API server port")

    # Security & CORS
    CORS_ORIGINS: List[str] = Field(
        default=["*"],
        description="Allowed CORS origins",
    )
    SECRET_KEY: str = Field(
        default="pahredaar-insecure-dev-secret-key-change-in-prod-32b",
        description="JWT and secret signing key",
    )

    # Storage & Persistence
    DB_PATH: Path = Field(
        default=BASE_DIR / "iot_ids.db",
        description="Path to SQLite database file",
    )

    # Models & ML Settings
    MODEL_DIR: Path = Field(
        default=BASE_DIR / "models",
        description="Directory containing serialized model artifacts",
    )
    GRACE_PERIOD_FLOWS: int = Field(
        default=15,
        description="Number of initial flows per device to observe before alerting",
    )

    # Logging
    LOG_LEVEL: str = Field(default="INFO", description="Logging level")
    LOG_JSON: bool = Field(default=False, description="Format logs as structured JSON")


settings = Settings()
