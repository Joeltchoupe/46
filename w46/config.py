"""
W46 Configuration — Single source of truth for all settings.
Loaded from environment variables with sensible defaults.
"""

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(str, Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class KMSProvider(str, Enum):
    LOCAL = "local"
    GCP = "gcp"
    FIREBLOCKS = "fireblocks"


class Settings(BaseSettings):
    """
    All W46 settings. Pydantic-settings reads from env vars automatically.
    Prefix: W46_ (except standard ones like GOOGLE_APPLICATION_CREDENTIALS).
    """

    model_config = SettingsConfigDict(
        env_prefix="W46_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Core ───────────────────────────────────────────────
    env: Environment = Environment.DEVELOPMENT
    secret_key: str = "change-me-to-64-hex-chars-in-production"
    api_host: str = "0.0.0.0"
    api_port: int = 8046
    log_level: str = "INFO"

    # ── PostgreSQL ─────────────────────────────────────────
    db_host: str = "localhost"
    db_port: int = 5432
    db_name: str = "w46"
    db_user: str = "w46"
    db_password: str = "change-me"
    db_pool_min: int = 5
    db_pool_max: int = 20

    # ── Redis ──────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── KMS ────────────────────────────────────────────────
    kms_provider: KMSProvider = KMSProvider.LOCAL

    # Local KMS
    kms_local_dir: str = "./data/keys"
    kms_local_passphrase: str = "dev-passphrase-change-me"

    # GCP KMS
    gcp_project_id: str = ""
    gcp_location: str = "global"
    gcp_keyring: str = "w46-keyring"
    gcp_key_id: str = "w46-master-key"

    # Fireblocks
    fireblocks_api_key: str = ""
    fireblocks_api_secret_path: str = ""
    fireblocks_base_url: str = "https://api.fireblocks.io"

    # ── Solana ─────────────────────────────────────────────
    solana_rpc_url: str = "https://api.mainnet-beta.solana.com"
    solana_rpc_url_fallback: str = ""
    solana_usdc_mint: str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    solana_commitment: str = "confirmed"
    solana_micro_payment_threshold_usdc: float = 50.0

    # ── Base (EVM L2) ─────────────────────────────────────
    base_rpc_url: str = "https://mainnet.base.org"
    base_rpc_url_fallback: str = ""
    base_chain_id: int = 8453
    base_usdc_contract: str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    base_commitment_registry: str = ""
    base_gas_price_gwei: float = 0.01

    # ── Routing ────────────────────────────────────────────
    routing_solana_max_usdc: float = 50.0
    routing_base_min_usdc: float = 500.0
    routing_circuit_breaker_threshold: int = 5
    routing_circuit_breaker_timeout_sec: int = 300

    # ── Fees ───────────────────────────────────────────────
    fee_solana_per_usdc: float = 0.005
    fee_base_per_usdc: float = 0.05
    fee_internal_per_usdc: float = 0.0
    fee_sweep_interval_sec: int = 3600

    # ── Operator Wallets ───────────────────────────────────
    operator_solana_address: str = ""
    operator_base_address: str = ""

    # ── Policy Defaults ────────────────────────────────────
    policy_default_max_per_tx: float = 1000.0
    policy_default_daily_limit: float = 10000.0
    policy_default_monthly_limit: float = 100000.0
    policy_default_human_approval_threshold: float = 5000.0
    policy_default_verified_rail_threshold: float = 500.0

    # ── Anchoring ──────────────────────────────────────────
    anchor_batch_size: int = 100
    anchor_solana_interval_sec: int = 600
    anchor_base_interval_sec: int = 600

    # ── Reconciliation ─────────────────────────────────────
    reconciliation_interval_sec: int = 300
    reconciliation_alert_webhook: str = ""

    # ── Auth ───────────────────────────────────────────────
    api_key_hash_iterations: int = 100_000
    session_ttl_sec: int = 86400
    rate_limit_per_minute: int = 120

    # ── Email ──────────────────────────────────────────────
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "noreply@w46.io"
    verification_token_ttl_sec: int = 3600

    # ── CORS ───────────────────────────────────────────────
    cors_origins: str = '["http://localhost:3000"]'

    # ── Derived Properties ─────────────────────────────────

    @property
    def dsn(self) -> str:
        return (
            f"postgresql://{self.db_user}:{self.db_password}"
            f"@{self.db_host}:{self.db_port}/{self.db_name}"
        )

    @property
    def async_dsn(self) -> str:
        return (
            f"postgresql://{self.db_user}:{self.db_password}"
            f"@{self.db_host}:{self.db_port}/{self.db_name}"
        )

    @property
    def is_production(self) -> bool:
        return self.env == Environment.PRODUCTION

    @property
    def cors_origins_list(self) -> List[str]:
        try:
            return json.loads(self.cors_origins)
        except (json.JSONDecodeError, TypeError):
            return ["http://localhost:3000"]

    def validate_production_guards(self) -> None:
        """Raise if production config is incomplete."""
        errors = []
        if self.is_production:
            if self.secret_key == "change-me-to-64-hex-chars-in-production":
                errors.append("W46_SECRET_KEY must be changed in production")
            if self.kms_provider == KMSProvider.LOCAL:
                errors.append("W46_KMS_PROVIDER cannot be 'local' in production")
            if not self.operator_solana_address:
                errors.append("W46_OPERATOR_SOLANA_ADDRESS required in production")
            if not self.operator_base_address:
                errors.append("W46_OPERATOR_BASE_ADDRESS required in production")
        if errors:
            raise ValueError(
                f"Production configuration errors:\n" + "\n".join(f"  - {e}" for e in errors)
            )


# ── Singleton ──────────────────────────────────────────────
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings() -> None:
    """For testing only."""
    global _settings
    _settings = None
