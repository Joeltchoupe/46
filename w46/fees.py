"""
W46 Fee Management — Per-USDC fee calculation and sweep.

Fees are calculated per USDC transferred (not per transaction).
Accumulated in fee_ledger, then swept hourly to operator wallets.

Fee rates:
- Solana:   $0.005 / USDC
- Base:     $0.05  / USDC
- Internal: $0.00  / USDC (free)
- Budget:   $0.00  / USDC (no USDC moves)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional
from uuid import UUID

import structlog

from w46 import db, audit
from w46.blockchain import get_chain_client
from w46.config import get_settings
from w46.kms import KeyReference, get_kms
from w46.models import TxRail

logger = structlog.get_logger(__name__)


def calculate_fee(amount_usdc: Decimal, rail: TxRail) -> Decimal:
    """Calculate fee for a given amount and rail."""
    settings = get_settings()

    rates = {
        TxRail.SOLANA: Decimal(str(settings.fee_solana_per_usdc)),
        TxRail.BASE: Decimal(str(settings.fee_base_per_usdc)),
        TxRail.INTERNAL: Decimal(str(settings.fee_internal_per_usdc)),
        TxRail.BUDGET_AUTH: Decimal("0"),
    }

    rate = rates.get(rail, Decimal("0"))
    return (amount_usdc * rate).quantize(Decimal("0.000001"))


async def get_pending_fees() -> Dict[str, Any]:
    """Get summary of unswept fees."""
    pool = db.get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT rail, COUNT(*) as count, SUM(amount_usdc) as total
            FROM fee_ledger
            WHERE swept = FALSE
            GROUP BY rail
            """
        )

    total = Decimal("0")
    by_rail = {}
    for row in rows:
        by_rail[row["rail"]] = {
            "count": row["count"],
            "total_usdc": str(row["total"]),
        }
        total += row["total"]

    return {
        "total_pending_usdc": str(total),
        "by_rail": by_rail,
    }


async def sweep_fees() -> Dict[str, Any]:
    """
    Sweep accumulated fees from agent wallets to operator wallets.
    
    Groups fees by chain, then executes a single transfer per chain.
    Marks swept fees in the ledger.
    """
    settings = get_settings()
    pool = db.get_pool()
    sweep_results = {}
    now = datetime.now(timezone.utc)

    async with pool.acquire() as conn:
        # ── Solana Sweep ───────────────────────────────────
        if settings.operator_solana_address:
            solana_fees = await conn.fetch(
                """
                SELECT fl.id, fl.wallet_id, fl.amount_usdc, w.solana_address, w.solana_key_ref
                FROM fee_ledger fl
                JOIN wallets w ON w.id = fl.wallet_id
                WHERE fl.swept = FALSE AND fl.rail = 'solana'
                  AND w.solana_address IS NOT NULL
                ORDER BY fl.created_at ASC
                LIMIT 100
                """
            )

            if solana_fees:
                total_solana = sum(row["amount_usdc"] for row in solana_fees)
                fee_ids = [row["id"] for row in solana_fees]

                try:
                    # Group by wallet and sweep each
                    by_wallet: Dict[UUID, List] = {}
                    for row in solana_fees:
                        wid = row["wallet_id"]
                        if wid not in by_wallet:
                            by_wallet[wid] = []
                        by_wallet[wid].append(row)

                    sweep_hashes = []
                    client = get_chain_client("solana")

                    for wid, wallet_fees in by_wallet.items():
                        amount = sum(f["amount_usdc"] for f in wallet_fees)
                        if amount <= 0:
                            continue

                        from_address = wallet_fees[0]["solana_address"]
                        key_ref_data = wallet_fees[0]["solana_key_ref"]

                        if not key_ref_data:
                            continue

                        key_ref_meta = json.loads(key_ref_data) if isinstance(key_ref_data, str) else key_ref_data
                        key_ref = KeyReference(
                            key_id=key_ref_meta.get("key_id", ""),
                            chain="solana",
                            metadata=key_ref_meta,
                        )

                        result = await client.transfer_usdc(
                            from_key_ref=key_ref,
                            from_address=from_address,
                            to_address=settings.operator_solana_address,
                            amount_usdc=amount,
                        )
                        sweep_hashes.append(result.get("tx_hash"))

                    # Mark as swept
                    await conn.execute(
                        """
                        UPDATE fee_ledger
                        SET swept = TRUE, swept_at = $1, sweep_tx_hash = $2
                        WHERE id = ANY($3)
                        """,
                        now,
                        sweep_hashes[0] if sweep_hashes else None,
                        fee_ids,
                    )

                    sweep_results["solana"] = {
                        "total_usdc": str(total_solana),
                        "fee_count": len(fee_ids),
                        "tx_hashes": sweep_hashes,
                    }

                    logger.info("fees.solana_swept", total=str(total_solana), count=len(fee_ids))

                except Exception as e:
                    logger.error("fees.solana_sweep_failed", error=str(e))
                    sweep_results["solana"] = {"error": str(e)}

        # ── Base Sweep ─────────────────────────────────────
        if settings.operator_base_address:
            base_fees = await conn.fetch(
                """
                SELECT fl.id, fl.wallet_id, fl.amount_usdc, w.base_address, w.base_key_ref
                FROM fee_ledger fl
                JOIN wallets w ON w.id = fl.wallet_id
                WHERE fl.swept = FALSE AND fl.rail = 'base'
                  AND w.base_address IS NOT NULL
                ORDER BY fl.created_at ASC
                LIMIT 100
                """
            )

            if base_fees:
                total_base = sum(row["amount_usdc"] for row in base_fees)
                fee_ids = [row["id"] for row in base_fees]

                try:
                    by_wallet: Dict[UUID, List] = {}
                    for row in base_fees:
                        wid = row["wallet_id"]
                        if wid not in by_wallet:
                            by_wallet[wid] = []
                        by_wallet[wid].append(row)

                    sweep_hashes = []
                    client = get_chain_client("base")

                    for wid, wallet_fees in by_wallet.items():
                        amount = sum(f["amount_usdc"] for f in wallet_fees)
                        if amount <= 0:
                            continue

                        from_address = wallet_fees[0]["base_address"]
                        key_ref_data = wallet_fees[0]["base_key_ref"]

                        if not key_ref_data:
                            continue

                        key_ref_meta = json.loads(key_ref_data) if isinstance(key_ref_data, str) else key_ref_data
                        key_ref = KeyReference(
                            key_id=key_ref_meta.get("key_id", ""),
                            chain="base",
                            metadata=key_ref_meta,
                        )

                        result = await client.transfer_usdc(
                            from_key_ref=key_ref,
                            from_address=from_address,
                            to_address=settings.operator_base_address,
                            amount_usdc=amount,
                        )
                        sweep_hashes.append(result.get("tx_hash"))

                    await conn.execute(
                        """
                        UPDATE fee_ledger
                        SET swept = TRUE, swept_at = $1, sweep_tx_hash = $2
                        WHERE id = ANY($3)
                        """,
                        now,
                        sweep_hashes[0] if sweep_hashes else None,
                        fee_ids,
                    )

                    sweep_results["base"] = {
                        "total_usdc": str(total_base),
                        "fee_count": len(fee_ids),
                        "tx_hashes": sweep_hashes,
                    }

                    logger.info("fees.base_swept", total=str(total_base), count=len(fee_ids))

                except Exception as e:
                    logger.error("fees.base_sweep_failed", error=str(e))
                    sweep_results["base"] = {"error": str(e)}

        # ── Audit ──────────────────────────────────────────
        if sweep_results:
            await audit.log(
                "fee_swept",
                "system",
                details=sweep_results,
                conn=conn,
            )

    return sweep_results
