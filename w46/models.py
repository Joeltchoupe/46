"""
W46 Models — Pydantic schemas for API requests, responses, and internal DTOs.

Strict validation, immutable where appropriate, with JSON-serializable outputs.
"""

from __future__ import annotations

import re
from datetime import datetime, date
from decimal import Decimal
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator


# ============================================================
# Enums (mirroring PostgreSQL enums)
# ============================================================

class EnvMode(str, Enum):
    SANDBOX = "sandbox"
    LIVE = "live"


class KYBStatus(str, Enum):
    NOT_STARTED = "not_started"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class WalletStatus(str, Enum):
    ACTIVE = "active"
    FROZEN = "frozen"
    CLOSED = "closed"


class TxStatus(str, Enum):
    PENDING_POLICY = "pending_policy"
    POLICY_REJECTED = "policy_rejected"
    POLICY_APPROVED = "policy_approved"
    PENDING_SETTLEMENT = "pending_settlement"
    SETTLING = "settling"
    SETTLED = "settled"
    FAILED = "failed"
    DEFERRED = "deferred"
    REVERSED = "reversed"


class TxRail(str, Enum):
    SOLANA = "solana"
    BASE = "base"
    INTERNAL = "internal"
    BUDGET_AUTH = "budget_auth"


# ============================================================
# Organization
# ============================================================

class OrgCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=200)
    email: str = Field(..., max_length=320)
    password: str = Field(..., min_length=12, max_length=128)

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, v.strip().lower()):
            raise ValueError("Invalid email address")
        return v.strip().lower()

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain an uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain a lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain a digit")
        return v


class OrgResponse(BaseModel):
    id: UUID
    name: str
    email: str
    email_verified: bool
    mode: EnvMode
    kyb_status: KYBStatus
    created_at: datetime

    model_config = {"from_attributes": True}


class EmailVerifyRequest(BaseModel):
    token: str = Field(..., min_length=32, max_length=128)


class TOSAcceptRequest(BaseModel):
    version: str = Field(..., min_length=1, max_length=20)


class KYBSubmitRequest(BaseModel):
    company_name: str = Field(..., min_length=2, max_length=200)
    registration_number: str = Field(..., min_length=1, max_length=100)
    country: str = Field(..., min_length=2, max_length=3)
    address: str = Field(..., min_length=5, max_length=500)
    beneficial_owners: List[Dict[str, Any]] = Field(default_factory=list)
    documents: Dict[str, str] = Field(default_factory=dict)  # doc_type -> url/reference


# ============================================================
# API Key
# ============================================================

class APIKeyCreateRequest(BaseModel):
    label: str = Field(default="default", max_length=100)
    mode: EnvMode = EnvMode.SANDBOX


class APIKeyResponse(BaseModel):
    id: UUID
    key_prefix: str
    label: str
    mode: EnvMode
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class APIKeyCreatedResponse(APIKeyResponse):
    """Only returned at creation — contains the full key. Never stored or shown again."""
    api_key: str


# ============================================================
# Wallet
# ============================================================

class WalletCreateRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=100, pattern=r"^[a-zA-Z0-9_\-\.]+$")
    label: Optional[str] = Field(default=None, max_length=200)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class WalletResponse(BaseModel):
    id: UUID
    org_id: UUID
    agent_id: str
    label: Optional[str]
    status: WalletStatus
    solana_address: Optional[str]
    base_address: Optional[str]
    balance_usdc: Decimal
    trust_score: int
    created_at: datetime

    model_config = {"from_attributes": True}


class WalletDetailResponse(WalletResponse):
    daily_spent: Decimal
    monthly_spent: Decimal
    afid_public_key: Optional[str]
    metadata: Dict[str, Any]
    updated_at: datetime


# ============================================================
# Policy
# ============================================================

class PolicyCreateRequest(BaseModel):
    max_per_tx_usdc: Decimal = Field(default=Decimal("1000"), gt=0)
    daily_limit_usdc: Decimal = Field(default=Decimal("10000"), gt=0)
    monthly_limit_usdc: Decimal = Field(default=Decimal("100000"), gt=0)
    allowed_categories: List[str] = Field(default_factory=list)
    blocked_destinations: List[str] = Field(default_factory=list)
    human_approval_threshold: Decimal = Field(default=Decimal("5000"), gt=0)
    verified_rail_threshold: Decimal = Field(default=Decimal("500"), gt=0)
    require_memo: bool = False


class PolicyResponse(BaseModel):
    id: UUID
    wallet_id: UUID
    max_per_tx_usdc: Decimal
    daily_limit_usdc: Decimal
    monthly_limit_usdc: Decimal
    allowed_categories: List[str]
    blocked_destinations: List[str]
    human_approval_threshold: Decimal
    verified_rail_threshold: Decimal
    require_memo: bool
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


# ============================================================
# Transaction / Payment
# ============================================================

class PaymentRequest(BaseModel):
    to_address: str = Field(..., min_length=1, max_length=200)
    amount_usdc: Decimal = Field(..., gt=0, le=Decimal("1000000"))
    memo: Optional[str] = Field(default=None, max_length=500)
    category: Optional[str] = Field(default=None, max_length=100)
    idempotency_key: Optional[str] = Field(default=None, max_length=128)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    preferred_rail: Optional[TxRail] = None


class TransactionResponse(BaseModel):
    id: UUID
    from_wallet_id: UUID
    to_address: str
    amount_usdc: Decimal
    fee_usdc: Decimal
    rail: Optional[TxRail]
    status: TxStatus
    tx_hash: Optional[str]
    proof_hash: Optional[str]
    memo: Optional[str]
    category: Optional[str]
    created_at: datetime
    settled_at: Optional[datetime]

    model_config = {"from_attributes": True}


class TransactionDetailResponse(TransactionResponse):
    org_id: UUID
    to_wallet_id: Optional[UUID]
    block_number: Optional[int]
    policy_snapshot: Optional[Dict[str, Any]]
    policy_result: Optional[Dict[str, Any]]
    budget_auth_token: Optional[str]
    budget_reconciled: Optional[bool]
    prev_proof_hash: Optional[str]
    idempotency_key: Optional[str]
    metadata: Dict[str, Any]
    error_message: Optional[str]
    updated_at: datetime


# ============================================================
# Proof & Anchoring
# ============================================================

class ProofVerifyResponse(BaseModel):
    wallet_id: UUID
    chain_valid: bool
    records_checked: int
    first_broken_at: Optional[UUID] = None
    message: str


class AnchorBatchResponse(BaseModel):
    id: UUID
    merkle_root: str
    tx_count: int
    solana_tx_hash: Optional[str]
    base_tx_hash: Optional[str]
    anchored_at: Optional[datetime]
    created_at: datetime

    model_config = {"from_attributes": True}


# ============================================================
# Reputation & AFID
# ============================================================

class ReputationResponse(BaseModel):
    wallet_id: UUID
    trust_score: int
    components: Dict[str, Any]


class AFIDResponse(BaseModel):
    wallet_id: UUID
    afid_public_key: Optional[str]
    trust_score: int
    capabilities: Dict[str, Any]
    verification_proof: str


# ============================================================
# Reconciliation
# ============================================================

class ReconciliationRunResponse(BaseModel):
    id: UUID
    wallet_id: UUID
    ledger_balance: Decimal
    chain_balance: Decimal
    chain: str
    matches: bool
    drift_usdc: Decimal
    created_at: datetime

    model_config = {"from_attributes": True}


# ============================================================
# Health / Meta
# ============================================================

class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str
    database: Dict[str, Any]
    redis: Dict[str, Any]
    blockchain: Dict[str, Any]


class ErrorResponse(BaseModel):
    error: Dict[str, Any]
