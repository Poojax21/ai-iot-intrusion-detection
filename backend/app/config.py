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

    # Phase 3: Open-Set Recognition Settings
    ENABLE_OPEN_SET: bool = Field(
        default=True,
        description="Enable Phase 3 open-set recognition layer",
    )
    OPEN_SET_MODEL_DIR: Path = Field(
        default=BASE_DIR / "models" / "open_set_v1",
        description="Directory containing open-set model artifacts",
    )
    OPEN_SET_CONFIDENCE_THRESHOLD: float = Field(
        default=0.70,
        description="Minimum multiclass confidence for known attacks",
    )
    OPEN_SET_NOVELTY_THRESHOLD: float = Field(
        default=1.25,
        description="Normalized distance factor beyond cluster boundary for OOD",
    )
    ALERT_SUPPRESSION_WINDOW_SEC: float = Field(
        default=5.0,
        description="Window in seconds to suppress duplicate alerts for the same device and attack",
    )

    # Phase 4: Advanced Hybrid AI Settings
    ENABLE_TREESHAP: bool = Field(
        default=True,
        description="Enable exact TreeSHAP explainability for tree models",
    )
    ENABLE_TEMPORAL: bool = Field(
        default=True,
        description="Enable temporal sequence modeling (LSTM / GRU)",
    )
    ENABLE_GRAPH: bool = Field(
        default=True,
        description="Enable communication graph intelligence",
    )
    ENABLE_HIERARCHICAL_RISK: bool = Field(
        default=True,
        description="Enable hierarchical multi-tier risk synthesis",
    )
    TEMPORAL_MODEL_DIR: Path = Field(
        default=BASE_DIR / "models" / "temporal_v1",
        description="Directory containing temporal sequence model artifacts",
    )
    GRAPH_MODEL_DIR: Path = Field(
        default=BASE_DIR / "models" / "graph_v1",
        description="Directory containing communication graph model artifacts",
    )

    # Logging
    LOG_LEVEL: str = Field(default="INFO", description="Logging level")
    LOG_JSON: bool = Field(default=False, description="Format logs as structured JSON")


settings = Settings()
