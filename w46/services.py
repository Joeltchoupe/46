"""
W46 Services — Business logic orchestration layer.

Sits between API routes and low-level modules.
Handles wallet creation (KMS + DB), payment orchestration, etc.
"""

from __future__ import annotations

import json
from decimal import Decimal
from typing import Any, Dict, List, Optional
from uuid import UUID

import asyncpg
import structlog

from w46 import audit, db
from w46.config import get_settings
from w46.exceptions import (
    DuplicateWalletError,
    KMSNotConfiguredError,
    WalletNotFoundError,
)
from w46.kms import KeyReference, get_kms, require_kms_for_production
from w46.models import TxRail, WalletStatus
from w46.policy import load_policy_snapshot
from w46.settlement import approve_human_review, process_payment

logger = structlog.get_logger(__name__)


# ============================================================
# Wallet Management
# ============================================================

async def create_wallet(
    org_id: UUID,
    agent_id: str,
    *,
    label: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    actor: str = "system",
    ip_address: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create a new wallet with blockchain addresses.
    
    Steps:
    1. Guard: check KMS is configured for production
    2. Generate Solana keypair via KMS
    3. Generate Base keypair via KMS
    4. Store wallet with addresses and key references
    5. Create default policy
    6. Audit log
    """
    require_kms_for_production()
    kms = get_kms()

    # Generate keypairs
    sol_ref, sol_address = await kms.generate_keypair("solana", label=f"{agent_id}_solana")
    base_ref, base_address = await kms.generate_keypair("base", label=f"{agent_id}_base")

    pool = db.get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            # Check duplicate
            existing = await conn.fetchval(
                "SELECT id FROM wallets WHERE org_id = $1 AND agent_id = $2",
                org_id,
                agent_id,
            )
            if existing:
                raise DuplicateWalletError(
                    details={"agent_id": agent_id, "existing_wallet_id": str(existing)}
                )

            # Insert wallet
            wallet_id = await conn.fetchval(
                """
                INSERT INTO wallets
                    (org_id, agent_id, label, solana_address, base_address,
                     solana_key_ref, base_key_ref, metadata)
                VALUES ($1, $2, $3, $4, $5, $6::text, $7::text, $8::jsonb)
                RETURNING id
                """,
                org_id,
                agent_id,
                label,
                sol_address,
                base_address,
                json.dumps(sol_ref.metadata),
                json.dumps(base_ref.metadata),
                json.dumps(metadata or {}),
            )

            # Create default policy
            settings = get_settings()
            await conn.execute(
                """
                INSERT INTO policies
                    (wallet_id, max_per_tx_usdc, daily_limit_usdc, monthly_limit_usdc,
                     human_approval_threshold, verified_rail_threshold)
                VALUES ($1, $2, $3, $4, $5, $6)
                """,
                wallet_id,
                Decimal(str(settings.policy_default_max_per_tx)),
                Decimal(str(settings.policy_default_daily_limit)),
                Decimal(str(settings.policy_default_monthly_limit)),
                Decimal(str(settings.policy_default_human_approval_threshold)),
                Decimal(str(settings.policy_default_verified_rail_threshold)),
            )

            # Audit
            await audit.log(
                "wallet_created",
                actor,
                org_id=org_id,
                wallet_id=wallet_id,
                details={
                    "agent_id": agent_id,
                    "solana_address": sol_address,
                    "base_address": base_address,
                },
                ip_address=ip_address,
                conn=conn,
            )

            # Fetch complete record
            wallet = await conn.fetchrow(
                "SELECT * FROM wallets WHERE id = $1",
                wallet_id,
            )

    logger.info(
        "service.wallet_created",
        wallet_id=str(wallet_id),
        agent_id=agent_id,
        solana=sol_address,
        base=base_address,
    )

    return dict(wallet)


async def get_wallet(org_id: UUID, wallet_id: UUID) -> Dict[str, Any]:
    """Get a wallet by ID, scoped to org."""
    row = await db.fetchrow(
        "SELECT * FROM wallets WHERE id = $1 AND org_id = $2",
        wallet_id,
        org_id,
    )
    if not row:
        raise WalletNotFoundError(details={"wallet_id": str(wallet_id)})
    return dict(row)


async def list_wallets(org_id: UUID, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    """List all wallets for an org."""
    rows = await db.fetch(
        """
        SELECT id, org_id, agent_id, label, status, solana_address, base_address,
               balance_usdc, trust_score, created_at
        FROM wallets
        WHERE org_id = $1
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3
        """,
        org_id,
        limit,
        offset,
    )
    return [dict(r) for r in rows]


async def freeze_wallet(
    org_id: UUID,
    wallet_id: UUID,
    actor: str = "system",
    ip_address: Optional[str] = None,
) -> Dict[str, Any]:
    """Freeze a wallet — blocks all outgoing transactions."""
    pool = db.get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            "UPDATE wallets SET status = 'frozen' WHERE id = $1 AND org_id = $2 AND status = 'active'",
            wallet_id,
            org_id,
        )
        if result == "UPDATE 0":
            raise WalletNotFoundError(details={"wallet_id": str(wallet_id)})

        await audit.log(
            "wallet_frozen",
            actor,
            org_id=org_id,
            wallet_id=wallet_id,
            ip_address=ip_address,
            conn=conn,
        )

    return {"wallet_id": str(wallet_id), "status": "frozen"}


async def close_wallet(
    org_id: UUID,
    wallet_id: UUID,
    actor: str = "system",
    ip_address: Optional[str] = None,
) -> Dict[str, Any]:
    """Close a wallet permanently."""
    pool = db.get_pool()
    async with pool.acquire() as conn:
        wallet = await conn.fetchrow(
            "SELECT balance_usdc FROM wallets WHERE id = $1 AND org_id = $2",
            wallet_id,
            org_id,
        )
        if not wallet:
            raise WalletNotFoundError()

        if wallet["balance_usdc"] > 0:
            raise ValueError(
                f"Cannot close wallet with balance {wallet['balance_usdc']} USDC. "
                "Withdraw all funds first."
            )

        await conn.execute(
            "UPDATE wallets SET status = 'closed' WHERE id = $1",
            wallet_id,
        )

        await audit.log(
            "wallet_closed",
            actor,
            org_id=org_id,
            wallet_id=wallet_id,
            ip_address=ip_address,
            conn=conn,
        )

    return {"wallet_id": str(wallet_id), "status": "closed"}


# ============================================================
# Policy Management
# ============================================================

async def update_policy(
    org_id: UUID,
    wallet_id: UUID,
    policy_data: Dict[str, Any],
    actor: str = "system",
    ip_address: Optional[str] = None,
) -> Dict[str, Any]:
    """Update the policy for a wallet (deactivate old, create new)."""
    pool = db.get_pool()
    async with pool.acquire() as conn:
        # Verify wallet ownership
        wallet = await conn.fetchrow(
            "SELECT id FROM wallets WHERE id = $1 AND org_id = $2",
            wallet_id,
            org_id,
        )
        if not wallet:
            raise WalletNotFoundError()

        async with conn.transaction():
            # Deactivate current policy
            await conn.execute(
                "UPDATE policies SET is_active = FALSE WHERE wallet_id = $1 AND is_active = TRUE",
                wallet_id,
            )

            # Create new
            policy_id = await conn.fetchval(
                """
                INSERT INTO policies
                    (wallet_id, max_per_tx_usdc, daily_limit_usdc, monthly_limit_usdc,
                     allowed_categories, blocked_destinations,
                     human_approval_threshold, verified_rail_threshold, require_memo)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                RETURNING id
                """,
                wallet_id,
                Decimal(str(policy_data.get("max_per_tx_usdc", 1000))),
                Decimal(str(policy_data.get("daily_limit_usdc", 10000))),
                Decimal(str(policy_data.get("monthly_limit_usdc", 100000))),
                policy_data.get("allowed_categories", []),
                policy_data.get("blocked_destinations", []),
                Decimal(str(policy_data.get("human_approval_threshold", 5000))),
                Decimal(str(policy_data.get("verified_rail_threshold", 500))),
                policy_data.get("require_memo", False),
            )

            await audit.log(
                "policy_updated",
                actor,
                org_id=org_id,
                wallet_id=wallet_id,
                details=policy_data,
                ip_address=ip_address,
                conn=conn,
            )

        row = await conn.fetchrow("SELECT * FROM policies WHERE id = $1", policy_id)
        return dict(row)


# ============================================================
# Transaction Queries
# ============================================================

async def get_transaction(org_id: UUID, tx_id: UUID) -> Dict[str, Any]:
    """Get a transaction by ID."""
    from w46.exceptions import TransactionNotFoundError

    row = await db.fetchrow(
        "SELECT * FROM transactions WHERE id = $1 AND org_id = $2",
        tx_id,
        org_id,
    )
    if not row:
        raise TransactionNotFoundError()
    return dict(row)


async def list_transactions(
    org_id: UUID,
    wallet_id: Optional[UUID] = None,
    limit: int = 50,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """List transactions for an org, optionally filtered by wallet."""
    if wallet_id:
        rows = await db.fetch(
            """
            SELECT * FROM transactions
            WHERE org_id = $1 AND from_wallet_id = $2
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            """,
            org_id,
            wallet_id,
            limit,
            offset,
        )
    else:
        rows = await db.fetch(
            """
            SELECT * FROM transactions
            WHERE org_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            """,
            org_id,
            limit,
            offset,
        )
    return [dict(r) for r in rows]
