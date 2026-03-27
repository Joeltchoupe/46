"""
W46 Settlement Engine — Executes the full payment pipeline.

Pipeline order:
1. Advisory lock on wallet
2. Idempotency check
3. Load policy snapshot
4. Evaluate policy (deterministic)
5. Select rail (routing engine)
6. Execute blockchain transfer (or internal/budget_auth)
7. Attach proof hash
8. Update ledger balances
9. Record fees
10. Audit log

If policy rejects → nothing moves. No gas, no fees, no blockchain tx.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, Optional
from uuid import UUID, uuid4

import asyncpg
import structlog

from w46 import db, audit
from w46.blockchain import get_chain_client
from w46.config import get_settings
from w46.exceptions import (
    AllRailsDownError,
    HumanApprovalRequiredError,
    IdempotencyConflictError,
    InsufficientBalanceError,
    PolicyViolationError,
    SettlementError,
    WalletClosedError,
    WalletFrozenError,
    WalletNotFoundError,
)
from w46.kms import KeyReference, get_kms
from w46.models import TxRail, TxStatus
from w46.policy import PaymentContext, PolicySnapshot, evaluate, load_policy_snapshot
from w46.proof import attach_proof
from w46.routing import RoutingDecision, record_rail_failure, record_rail_success, select_rail

logger = structlog.get_logger(__name__)


async def process_payment(
    org_id: UUID,
    wallet_id: UUID,
    to_address: str,
    amount_usdc: Decimal,
    *,
    memo: Optional[str] = None,
    category: Optional[str] = None,
    idempotency_key: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    preferred_rail: Optional[TxRail] = None,
    actor: str = "system",
    ip_address: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Full payment pipeline. This is the main entry point.

    Returns the transaction record as a dict.
    """
    settings = get_settings()
    pool = db.get_pool()
    tx_id = uuid4()
    now = datetime.now(timezone.utc)

    async with pool.acquire() as conn:
        # ── Step 1: Advisory Lock ──────────────────────────
        async with db.wallet_lock(conn, str(wallet_id)):

            # ── Step 2: Idempotency Check ──────────────────
            if idempotency_key:
                existing = await conn.fetchrow(
                    """
                    SELECT id, org_id, from_wallet_id, to_address, amount_usdc,
                           fee_usdc, rail, status, tx_hash, proof_hash,
                           memo, category, created_at, settled_at
                    FROM transactions 
                    WHERE idempotency_key = $1 AND org_id = $2
                    """,
                    idempotency_key,
                    org_id,
                )
                if existing:
                    logger.info(
                        "settlement.idempotent_hit",
                        idempotency_key=idempotency_key,
                        tx_id=str(existing["id"]),
                    )
                    return dict(existing)

            # ── Load Wallet ────────────────────────────────
            wallet = await conn.fetchrow(
                """
                SELECT id, org_id, agent_id, status, solana_address, base_address,
                       solana_key_ref, base_key_ref, balance_usdc,
                       daily_spent, daily_reset_at, monthly_spent, monthly_reset_at
                FROM wallets
                WHERE id = $1 AND org_id = $2
                FOR UPDATE
                """,
                wallet_id,
                org_id,
            )

            if not wallet:
                raise WalletNotFoundError(details={"wallet_id": str(wallet_id)})

            if wallet["status"] == "frozen":
                raise WalletFrozenError(details={"wallet_id": str(wallet_id)})
            if wallet["status"] == "closed":
                raise WalletClosedError(details={"wallet_id": str(wallet_id)})

            # ── Check if destination is internal W46 wallet ─
            # SECURITY: scoped to same org only — prevents cross-org internal routing
            to_wallet = await conn.fetchrow(
                """
                SELECT id, org_id, solana_address, base_address, status
                FROM wallets
                WHERE (solana_address = $1 OR base_address = $1)
                  AND org_id = $2
                  AND status = 'active'
                """,
                to_address,
                org_id,
            )

            to_wallet_id = to_wallet["id"] if to_wallet else None
            to_org_id = str(to_wallet["org_id"]) if to_wallet else None

            # ── Step 3: Load Policy ────────────────────────
            policy_snapshot = await load_policy_snapshot(conn, wallet_id)

            # ── Step 4: Evaluate Policy ────────────────────
            ctx = PaymentContext(
                wallet_id=wallet_id,
                wallet_status=wallet["status"],
                amount_usdc=amount_usdc,
                to_address=to_address,
                category=category,
                memo=memo,
                daily_spent=wallet["daily_spent"],
                monthly_spent=wallet["monthly_spent"],
                daily_reset_at=wallet["daily_reset_at"],
                monthly_reset_at=wallet["monthly_reset_at"],
            )

            policy_result = evaluate(ctx, policy_snapshot)

            # ── Policy Rejected → Record and Stop ──────────
            if not policy_result.approved:
                await conn.execute(
                    """
                    INSERT INTO transactions
                        (id, org_id, from_wallet_id, to_address, to_wallet_id,
                         amount_usdc, status, policy_snapshot, policy_result,
                         memo, category, idempotency_key, metadata, created_at)
                    VALUES ($1, $2, $3, $4, $5, $6, 'policy_rejected'::tx_status,
                            $7::jsonb, $8::jsonb, $9, $10, $11, $12::jsonb, $13)
                    """,
                    tx_id, org_id, wallet_id, to_address, to_wallet_id,
                    amount_usdc,
                    json.dumps(policy_snapshot.to_dict()),
                    json.dumps(policy_result.to_dict()),
                    memo, category, idempotency_key,
                    json.dumps(metadata or {}),
                    now,
                )

                await audit.log(
                    "tx_policy_checked",
                    actor,
                    org_id=org_id,
                    wallet_id=wallet_id,
                    tx_id=tx_id,
                    details={"approved": False, "reason": policy_result.reason},
                    ip_address=ip_address,
                    conn=conn,
                )

                raise PolicyViolationError(
                    message=policy_result.reason,
                    details={"tx_id": str(tx_id), "checks": policy_result.checks},
                )

            # ── Human Approval Required → Park and Wait ───
            if policy_result.requires_human_approval:
                await conn.execute(
                    """
                    INSERT INTO transactions
                        (id, org_id, from_wallet_id, to_address, to_wallet_id,
                         amount_usdc, status, policy_snapshot, policy_result,
                         memo, category, idempotency_key, metadata, created_at)
                    VALUES ($1, $2, $3, $4, $5, $6, 'pending_policy'::tx_status,
                            $7::jsonb, $8::jsonb, $9, $10, $11, $12::jsonb, $13)
                    """,
                    tx_id, org_id, wallet_id, to_address, to_wallet_id,
                    amount_usdc,
                    json.dumps(policy_snapshot.to_dict()),
                    json.dumps(policy_result.to_dict()),
                    memo, category, idempotency_key,
                    json.dumps(metadata or {}),
                    now,
                )

                await audit.log(
                    "human_approval_requested",
                    actor,
                    org_id=org_id,
                    wallet_id=wallet_id,
                    tx_id=tx_id,
                    details={"amount": str(amount_usdc)},
                    ip_address=ip_address,
                    conn=conn,
                )

                raise HumanApprovalRequiredError(
                    message=f"Amount {amount_usdc} USDC requires human approval",
                    details={"tx_id": str(tx_id)},
                )

            # ── Step 5: Select Rail ────────────────────────
            routing = select_rail(
                amount_usdc=amount_usdc,
                to_address=to_address,
                from_org_id=str(org_id),
                to_wallet_id=str(to_wallet_id) if to_wallet_id else None,
                to_org_id=to_org_id,
                requires_verified_rail=policy_result.requires_verified_rail,
                preferred_rail=preferred_rail,
            )

            # ── All Rails Down → Defer ─────────────────────
            if routing.estimated_time_sec < 0:
                await conn.execute(
                    """
                    INSERT INTO transactions
                        (id, org_id, from_wallet_id, to_address, to_wallet_id,
                         amount_usdc, rail, status, policy_snapshot, policy_result,
                         memo, category, idempotency_key, metadata, created_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7::tx_rail, 'deferred'::tx_status,
                            $8::jsonb, $9::jsonb, $10, $11, $12, $13::jsonb, $14)
                    """,
                    tx_id, org_id, wallet_id, to_address, to_wallet_id,
                    amount_usdc, routing.rail.value,
                    json.dumps(policy_snapshot.to_dict()),
                    json.dumps(policy_result.to_dict()),
                    memo, category, idempotency_key,
                    json.dumps(metadata or {}),
                    now,
                )

                await audit.log(
                    "tx_deferred",
                    actor,
                    org_id=org_id,
                    wallet_id=wallet_id,
                    tx_id=tx_id,
                    details={"reason": "all rails down"},
                    ip_address=ip_address,
                    conn=conn,
                )

                raise AllRailsDownError(details={"tx_id": str(tx_id)})

            # ── Calculate Fee ──────────────────────────────
            fee_usdc = amount_usdc * routing.fee_per_usdc

            # ── Ledger Balance Check (fast, pre-chain) ─────
            total_debit = amount_usdc + fee_usdc
            if wallet["balance_usdc"] < total_debit:
                raise InsufficientBalanceError(
                    message=f"Ledger balance {wallet['balance_usdc']} < {total_debit} USDC needed",
                    details={
                        "balance": str(wallet["balance_usdc"]),
                        "amount": str(amount_usdc),
                        "fee": str(fee_usdc),
                        "total_needed": str(total_debit),
                    },
                )

            # ── Step 6: Insert TX as Settling ──────────────
            await conn.execute(
                """
                INSERT INTO transactions
                    (id, org_id, from_wallet_id, to_address, to_wallet_id,
                     amount_usdc, fee_usdc, rail, status,
                     policy_snapshot, policy_result,
                     memo, category, idempotency_key, metadata, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8::tx_rail, 'settling'::tx_status,
                        $9::jsonb, $10::jsonb, $11, $12, $13, $14::jsonb, $15)
                """,
                tx_id, org_id, wallet_id, to_address, to_wallet_id,
                amount_usdc, fee_usdc, routing.rail.value,
                json.dumps(policy_snapshot.to_dict()),
                json.dumps(policy_result.to_dict()),
                memo, category, idempotency_key,
                json.dumps(metadata or {}),
                now,
            )

            # ── Execute Blockchain Transfer ────────────────
            try:
                chain_result = await _execute_rail(
                    conn=conn,
                    wallet=wallet,
                    to_address=to_address,
                    to_wallet=to_wallet,
                    amount_usdc=amount_usdc,
                    routing=routing,
                    org_id=org_id,
                )
            except Exception as e:
                # Settlement failed — mark and re-raise
                record_rail_failure(routing.rail.value)

                await conn.execute(
                    """
                    UPDATE transactions
                    SET status = 'failed', error_message = $1
                    WHERE id = $2
                    """,
                    str(e)[:1000],
                    tx_id,
                )

                await audit.log(
                    "tx_failed",
                    actor,
                    org_id=org_id,
                    wallet_id=wallet_id,
                    tx_id=tx_id,
                    details={"error": str(e)[:500], "rail": routing.rail.value},
                    ip_address=ip_address,
                    conn=conn,
                )

                raise SettlementError(
                    message=f"Settlement failed on {routing.rail.value}: {e}",
                    details={"tx_id": str(tx_id), "rail": routing.rail.value},
                )

            # ── Step 6b: Settlement Succeeded ──────────────
            record_rail_success(routing.rail.value)
            settled_at = datetime.now(timezone.utc)

            tx_hash = chain_result.get("tx_hash")
            block_number = chain_result.get("block_number") or chain_result.get("slot")

            # ── Step 7: Attach Proof Hash ──────────────────
            proof_hash = await attach_proof(
                conn=conn,
                tx_id=tx_id,
                wallet_id=wallet_id,
                tx_hash=tx_hash,
                rail=routing.rail.value,
                amount_usdc=amount_usdc,
                fee_usdc=fee_usdc,
                to_address=to_address,
                policy_snapshot=policy_snapshot.to_dict(),
                settled_at=settled_at,
            )

            # ── Step 8: Update Transaction Record ──────────
            await conn.execute(
                """
                UPDATE transactions
                SET status = 'settled',
                    tx_hash = $1,
                    block_number = $2,
                    settled_at = $3
                WHERE id = $4
                """,
                tx_hash,
                block_number,
                settled_at,
                tx_id,
            )

            # ── Step 8b: Update Ledger Balances ────────────

            # Debit sender (amount + fee)
            await conn.execute(
                """
                UPDATE wallets
                SET balance_usdc = balance_usdc - $1 - $2,
                    daily_spent = daily_spent + $1,
                    monthly_spent = monthly_spent + $1
                WHERE id = $3
                """,
                amount_usdc,
                fee_usdc,
                wallet_id,
            )

            # Credit receiver if internal transfer
            if to_wallet_id and routing.rail == TxRail.INTERNAL:
                async with db.wallet_lock(conn, str(to_wallet_id)):
                    await conn.execute(
                        """
                        UPDATE wallets
                        SET balance_usdc = balance_usdc + $1
                        WHERE id = $2
                        """,
                        amount_usdc,
                        to_wallet_id,
                    )

                    # Attach proof on receiver side too for A2A
                    await attach_proof(
                        conn=conn,
                        tx_id=tx_id,
                        wallet_id=to_wallet_id,
                        tx_hash=tx_hash,
                        rail=routing.rail.value,
                        amount_usdc=amount_usdc,
                        fee_usdc=Decimal("0"),
                        to_address=to_address,
                        policy_snapshot=policy_snapshot.to_dict(),
                        settled_at=settled_at,
                    )

            # ── Step 9: Record Fee ─────────────────────────
            if fee_usdc > 0:
                await conn.execute(
                    """
                    INSERT INTO fee_ledger (tx_id, wallet_id, amount_usdc, rail)
                    VALUES ($1, $2, $3, $4::tx_rail)
                    """,
                    tx_id,
                    wallet_id,
                    fee_usdc,
                    routing.rail.value,
                )

            # ── Step 10: Audit Log ─────────────────────────
            await audit.log(
                "tx_settled",
                actor,
                org_id=org_id,
                wallet_id=wallet_id,
                tx_id=tx_id,
                details={
                    "amount_usdc": str(amount_usdc),
                    "fee_usdc": str(fee_usdc),
                    "rail": routing.rail.value,
                    "tx_hash": tx_hash,
                    "block_number": block_number,
                    "proof_hash": proof_hash,
                    "to_address": to_address,
                    "to_wallet_id": str(to_wallet_id) if to_wallet_id else None,
                    "routing": routing.to_dict(),
                },
                ip_address=ip_address,
                conn=conn,
            )

            logger.info(
                "settlement.complete",
                tx_id=str(tx_id),
                amount=str(amount_usdc),
                fee=str(fee_usdc),
                rail=routing.rail.value,
                tx_hash=tx_hash,
            )

            # ── Return Final Transaction Record ────────────
            row = await conn.fetchrow(
                """
                SELECT id, org_id, from_wallet_id, to_address, to_wallet_id,
                       amount_usdc, fee_usdc, rail, status, tx_hash,
                       block_number, settled_at, proof_hash, prev_proof_hash,
                       policy_snapshot, policy_result,
                       memo, category, idempotency_key, metadata,
                       error_message, created_at, updated_at
                FROM transactions
                WHERE id = $1
                """,
                tx_id,
            )
            return dict(row)


async def _execute_rail(
    conn: asyncpg.Connection,
    wallet: asyncpg.Record,
    to_address: str,
    to_wallet: Optional[asyncpg.Record],
    amount_usdc: Decimal,
    routing: RoutingDecision,
    org_id: UUID,
) -> Dict[str, Any]:
    """
    Execute the actual transfer based on the selected rail.

    Internal: ledger-only update, no blockchain involved.
    Budget auth: no USDC moves, just reserve and issue token.
    Solana/Base: real on-chain SPL/ERC-20 transfer via KMS signing.
    """

    # ── Internal Rail ──────────────────────────────────────
    if routing.rail == TxRail.INTERNAL:
        logger.info(
            "settlement.internal_transfer",
            from_wallet=str(wallet["id"]),
            to_wallet=str(to_wallet["id"]) if to_wallet else None,
            amount=str(amount_usdc),
        )
        return {
            "tx_hash": f"internal_{uuid4().hex}",
            "confirmed": True,
            "chain": "internal",
        }

    # ── Budget Authorization Rail ──────────────────────────
    if routing.rail == TxRail.BUDGET_AUTH:
        budget_token = uuid4().hex
        logger.info(
            "settlement.budget_auth",
            from_wallet=str(wallet["id"]),
            budget_token=budget_token,
            amount=str(amount_usdc),
        )

        # Store budget auth token on the transaction
        await conn.execute(
            """
            UPDATE transactions
            SET budget_auth_token = $1
            WHERE id = (
                SELECT id FROM transactions
                WHERE from_wallet_id = $2
                ORDER BY created_at DESC
                LIMIT 1
            )
            """,
            budget_token,
            wallet["id"],
        )

        return {
            "tx_hash": f"budget_{budget_token}",
            "budget_auth_token": budget_token,
            "confirmed": True,
            "chain": "budget_auth",
        }

    # ── Blockchain Rails (Solana / Base) ───────────────────

    chain_client = get_chain_client(routing.rail)

    # Select the right address and key ref for the chosen rail
    if routing.rail == TxRail.SOLANA:
        from_address = wallet["solana_address"]
        key_ref_data = wallet["solana_key_ref"]
    elif routing.rail == TxRail.BASE:
        from_address = wallet["base_address"]
        key_ref_data = wallet["base_key_ref"]
    else:
        raise SettlementError(f"Unknown blockchain rail: {routing.rail.value}")

    if not from_address:
        raise SettlementError(
            f"Wallet {wallet['id']} has no {routing.rail.value} address",
            details={"wallet_id": str(wallet["id"]), "rail": routing.rail.value},
        )

    if not key_ref_data:
        raise SettlementError(
            f"Wallet {wallet['id']} has no {routing.rail.value} key reference",
            details={"wallet_id": str(wallet["id"]), "rail": routing.rail.value},
        )

    # Reconstruct KeyReference from stored JSON
    key_ref_meta = json.loads(key_ref_data) if isinstance(key_ref_data, str) else key_ref_data
    key_ref = KeyReference(
        key_id=key_ref_meta.get("key_id", ""),
        chain=routing.rail.value,
        metadata=key_ref_meta,
    )

    # ── Verify On-Chain Balance Before Sending ─────────────
    # This is the SOURCE OF TRUTH check — ledger is just a mirror
    try:
        on_chain_balance = await chain_client.get_usdc_balance(from_address)
    except Exception as e:
        raise SettlementError(
            f"Failed to check on-chain balance on {routing.rail.value}: {e}",
            details={"address": from_address, "rail": routing.rail.value},
        )

    if on_chain_balance < amount_usdc:
        raise InsufficientBalanceError(
            message=(
                f"On-chain balance {on_chain_balance} USDC "
                f"< {amount_usdc} USDC required on {routing.rail.value}"
            ),
            details={
                "on_chain_balance": str(on_chain_balance),
                "requested": str(amount_usdc),
                "chain": routing.rail.value,
                "address": from_address,
            },
        )

    logger.info(
        "settlement.executing_transfer",
        rail=routing.rail.value,
        from_address=from_address,
        to_address=to_address,
        amount=str(amount_usdc),
        on_chain_balance=str(on_chain_balance),
    )

   # ── Execute The Actual Blockchain Transfer ─────────────
    result = await chain_client.transfer_usdc(
        from_key_ref=key_ref,
        from_address=from_address,
        to_address=to_address,
        amount_usdc=amount_usdc,
    )

    logger.info(
        "settlement.transfer_confirmed",
        rail=routing.rail.value,
        tx_hash=result.get("tx_hash"),
        block=result.get("block_number") or result.get("slot"),
    )

    return result


async def approve_human_review(
    tx_id: UUID,
    org_id: UUID,
    approved: bool,
    actor: str = "admin",
    ip_address: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Approve or deny a transaction that requires human approval.

    If approved, resumes the full settlement pipeline from scratch
    (re-evaluates policy, re-checks balance, re-selects rail).

    If denied, marks as policy_rejected permanently.
    """
    pool = db.get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT id, org_id, from_wallet_id, to_address, amount_usdc,
                   memo, category, metadata
            FROM transactions
            WHERE id = $1 AND org_id = $2 AND status = 'pending_policy'
            """,
            tx_id,
            org_id,
        )

        if not row:
            raise ValueError(
                f"Transaction {tx_id} not found, not owned by org, or not pending approval"
            )

        if approved:
            await audit.log(
                "human_approval_granted",
                actor,
                org_id=org_id,
                wallet_id=row["from_wallet_id"],
                tx_id=tx_id,
                details={"amount": str(row["amount_usdc"])},
                ip_address=ip_address,
                conn=conn,
            )

    # Mark old tx as superseded
            await conn.execute(
                """
                UPDATE transactions
                SET status = 'policy_approved',
                    error_message = 'Human approved — re-processing'
                WHERE id = $1
                """,
                tx_id,
            )

            # Re-run the full pipeline with a fresh transaction
            # This ensures current balance, policy, and rail state are used
            tx_metadata = json.loads(row["metadata"]) if row["metadata"] else None
            return await process_payment(
                org_id=org_id,
                wallet_id=row["from_wallet_id"],
                to_address=row["to_address"],
                amount_usdc=row["amount_usdc"],
                memo=row["memo"],
                category=row["category"],
                metadata=tx_metadata,
                actor=actor,
                ip_address=ip_address,
                )
        else:
            await conn.execute(
                """
                UPDATE transactions
                SET status = 'policy_rejected',
                    error_message = 'Human review denied'
                WHERE id = $1
                """,
                tx_id,
            )

            await audit.log(
                "human_approval_denied",
                actor,
                org_id=org_id,
                wallet_id=row["from_wallet_id"],
                tx_id=tx_id,
                details={"amount": str(row["amount_usdc"])},
                ip_address=ip_address,
                conn=conn,
            )

           return {
                "tx_id": str(tx_id),
                "status": "policy_rejected",
                "message": "Transaction denied by human reviewer",
           }
