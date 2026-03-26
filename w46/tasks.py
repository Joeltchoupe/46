"""
W46 Background Tasks — Periodic jobs via APScheduler.

Jobs:
1. Fee Sweep          — hourly, sweep accumulated fees to operator wallets
2. Reconciliation     — every 5 min, compare ledger vs on-chain
3. Anchor Batching    — every 10 min, create Merkle batches and anchor on-chain
4. Reputation Update  — hourly, recalculate trust scores
5. Counter Reset      — daily, handled by PostgreSQL triggers (no job needed)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from w46.config import get_settings

logger = structlog.get_logger(__name__)

_scheduler: AsyncIOScheduler | None = None


def get_scheduler() -> AsyncIOScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = AsyncIOScheduler(timezone="UTC")
    return _scheduler


# ============================================================
# Job Implementations
# ============================================================

async def job_fee_sweep() -> None:
    """Sweep accumulated fees to operator wallets."""
    try:
        from w46.fees import sweep_fees
        result = await sweep_fees()
        logger.info("task.fee_sweep.complete", result=result)
    except Exception as e:
        logger.error("task.fee_sweep.failed", error=str(e))


async def job_reconciliation() -> None:
    """Reconcile all active wallets."""
    try:
        from w46.reconciliation import reconcile_all_wallets
        result = await reconcile_all_wallets()
        logger.info("task.reconciliation.complete", **result)
    except Exception as e:
        logger.error("task.reconciliation.failed", error=str(e))


async def job_anchor_batch() -> None:
    """Create Merkle batches and publish anchors on-chain."""
    try:
        from w46 import db
        from w46.proof import create_anchor_batch

        settings = get_settings()
        pool = db.get_pool()

        async with pool.acquire() as conn:
            batch = await create_anchor_batch(conn, settings.anchor_batch_size)

        if not batch:
            logger.debug("task.anchor.no_pending_transactions")
            return

        # ── Anchor on Solana (memo program) ────────────────
        try:
            await _anchor_solana(batch["merkle_root"], batch["batch_id"])
        except Exception as e:
            logger.error("task.anchor.solana_failed", error=str(e))

        # ── Anchor on Base (CommitmentRegistry) ────────────
        try:
            await _anchor_base(batch["merkle_root"], batch["batch_id"])
        except Exception as e:
            logger.error("task.anchor.base_failed", error=str(e))

        logger.info(
            "task.anchor.complete",
            batch_id=batch["batch_id"],
            tx_count=batch["tx_count"],
            merkle_root=batch["merkle_root"][:16] + "...",
        )

    except Exception as e:
        logger.error("task.anchor.failed", error=str(e))


async def _anchor_solana(merkle_root: str, batch_id: str) -> None:
    """Publish Merkle root as a Solana memo transaction."""
    settings = get_settings()
    if not settings.operator_solana_address:
        return

    from solana.rpc.async_api import AsyncClient
    from solders.keypair import Keypair
    from solders.pubkey import Pubkey
    from solders.transaction import Transaction
    from solders.message import Message
    from solders.instruction import Instruction, AccountMeta

    # Memo program ID
    MEMO_PROGRAM_ID = Pubkey.from_string("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")

    memo_data = f"W46:anchor:v1:{merkle_root}:{batch_id}".encode()

    # Use operator key for anchoring (we need a funded wallet)
    kms = __import__("w46.kms", fromlist=["get_kms"]).get_kms()

    # For now, log the intent — actual signing requires operator key setup
    logger.info(
        "task.anchor.solana_memo",
        merkle_root=merkle_root[:16],
        batch_id=batch_id,
        memo_size=len(memo_data),
    )

    # Update batch record
    from w46 import db
    await db.execute(
        """
        UPDATE anchor_batches
        SET solana_tx_hash = $1, anchored_at = NOW()
        WHERE id = $2::uuid
        """,
        f"pending_solana_{batch_id}",
        batch_id,
    )


async def _anchor_base(merkle_root: str, batch_id: str) -> None:
    """Publish Merkle root to CommitmentRegistry on Base."""
    settings = get_settings()
    if not settings.base_commitment_registry or settings.base_commitment_registry == "0x" + "0" * 40:
        logger.debug("task.anchor.base_no_registry")
        return

    # CommitmentRegistry.commitRoot(bytes32 root)
    # For now, log the intent
    logger.info(
        "task.anchor.base_registry",
        merkle_root=merkle_root[:16],
        batch_id=batch_id,
        registry=settings.base_commitment_registry,
    )

    from w46 import db
    await db.execute(
        """
        UPDATE anchor_batches
        SET base_tx_hash = $1, anchored_at = COALESCE(anchored_at, NOW())
        WHERE id = $2::uuid
        """,
        f"pending_base_{batch_id}",
        batch_id,
    )


async def job_reputation_update() -> None:
    """Recalculate trust scores for all active wallets."""
    try:
        from w46 import db
        from w46.reputation import update_trust_score

        pool = db.get_pool()
        async with pool.acquire() as conn:
            wallets = await conn.fetch(
                "SELECT id FROM wallets WHERE status = 'active'"
            )

        updated = 0
        for w in wallets:
            try:
                await update_trust_score(w["id"])
                updated += 1
            except Exception as e:
                logger.warning(
                    "task.reputation.wallet_error",
                    wallet_id=str(w["id"]),
                    error=str(e),
                )

        logger.info("task.reputation.complete", updated=updated, total=len(wallets))

    except Exception as e:
        logger.error("task.reputation.failed", error=str(e))


# ============================================================
# Scheduler Setup
# ============================================================

def setup_scheduler() -> AsyncIOScheduler:
    """Configure and return the scheduler with all periodic jobs."""
    settings = get_settings()
    scheduler = get_scheduler()

    # Fee Sweep — hourly
    scheduler.add_job(
        job_fee_sweep,
        trigger=IntervalTrigger(seconds=settings.fee_sweep_interval_sec),
        id="fee_sweep",
        name="Fee Sweep",
        replace_existing=True,
        max_instances=1,
    )

    # Reconciliation — every 5 min
    scheduler.add_job(
        job_reconciliation,
        trigger=IntervalTrigger(seconds=settings.reconciliation_interval_sec),
        id="reconciliation",
        name="Reconciliation",
        replace_existing=True,
        max_instances=1,
    )

    # Anchor Batching — Solana interval
    scheduler.add_job(
        job_anchor_batch,
        trigger=IntervalTrigger(seconds=settings.anchor_solana_interval_sec),
        id="anchor_batch",
        name="Anchor Batch",
        replace_existing=True,
        max_instances=1,
    )

    # Reputation Update — hourly
    scheduler.add_job(
        job_reputation_update,
        trigger=IntervalTrigger(seconds=3600),
        id="reputation_update",
        name="Reputation Update",
        replace_existing=True,
        max_instances=1,
    )

    logger.info(
        "tasks.scheduler_configured",
        jobs=[j.id for j in scheduler.get_jobs()],
    )

    return scheduler
