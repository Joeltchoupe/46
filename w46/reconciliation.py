"""
W46 Reconciliation — Compares ledger balances vs on-chain balances.

The PostgreSQL ledger is an operational MIRROR.
The blockchain is the SOURCE OF TRUTH.

This module:
1. Reads the ledger balance for each wallet
2. Queries the actual on-chain balance (Solana + Base)
3. Compares them
4. Records the result
5. Fires alerts on mismatch
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional
from uuid import UUID

import httpx
import structlog

from w46 import db, audit
from w46.blockchain import get_chain_client
from w46.config import get_settings

logger = structlog.get_logger(__name__)

# Acceptable drift before triggering alert (covers rounding, in-flight tx)
ACCEPTABLE_DRIFT_USDC = Decimal("0.01")


async def reconcile_wallet(
    wallet_id: UUID,
    *,
    alert_on_mismatch: bool = True,
) -> List[Dict[str, Any]]:
    """
    Reconcile a single wallet across all chains.
    
    Returns a list of reconciliation results (one per chain).
    """
    pool = db.get_pool()
    results = []

    async with pool.acquire() as conn:
        wallet = await conn.fetchrow(
            """
            SELECT id, org_id, solana_address, base_address, balance_usdc
            FROM wallets WHERE id = $1
            """,
            wallet_id,
        )

        if not wallet:
            return [{"error": f"Wallet {wallet_id} not found"}]

        ledger_balance = wallet["balance_usdc"]

        # ── Check each chain ───────────────────────────────
        for chain, address_col in [("solana", "solana_address"), ("base", "base_address")]:
            address = wallet[address_col]
            if not address:
                continue

            try:
                client = get_chain_client(chain)
                chain_balance = await client.get_usdc_balance(address)
            except Exception as e:
                logger.warning(
                    "reconciliation.chain_error",
                    wallet_id=str(wallet_id),
                    chain=chain,
                    error=str(e),
                )
                results.append({
                    "wallet_id": str(wallet_id),
                    "chain": chain,
                    "error": str(e),
                    "matches": None,
                })
                continue

            drift = abs(chain_balance - ledger_balance)
            matches = drift <= ACCEPTABLE_DRIFT_USDC

            # Record the run
            run_id = await conn.fetchval(
                """
                INSERT INTO reconciliation_runs
                    (wallet_id, ledger_balance, chain_balance, chain, matches, drift_usdc)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING id
                """,
                wallet_id,
                ledger_balance,
                chain_balance,
                chain,
                matches,
                drift,
            )

            run_result = {
                "run_id": str(run_id),
                "wallet_id": str(wallet_id),
                "chain": chain,
                "ledger_balance": str(ledger_balance),
                "chain_balance": str(chain_balance),
                "drift_usdc": str(drift),
                "matches": matches,
            }
            results.append(run_result)

            if not matches:
                logger.error(
                    "reconciliation.MISMATCH",
                    wallet_id=str(wallet_id),
                    chain=chain,
                    ledger=str(ledger_balance),
                    on_chain=str(chain_balance),
                    drift=str(drift),
                )

                await audit.log(
                    "reconciliation_mismatch",
                    "system",
                    org_id=wallet["org_id"],
                    wallet_id=wallet_id,
                    details=run_result,
                    conn=conn,
                )

                if alert_on_mismatch:
                    await _fire_alert(run_result)
            else:
                logger.debug(
                    "reconciliation.match",
                    wallet_id=str(wallet_id),
                    chain=chain,
                    balance=str(chain_balance),
                )

    return results


async def reconcile_all_wallets() -> Dict[str, Any]:
    """
    Reconcile all active wallets.
    
    Returns summary statistics.
    """
    pool = db.get_pool()
    async with pool.acquire() as conn:
        wallets = await conn.fetch(
            "SELECT id FROM wallets WHERE status = 'active'"
        )

    total = len(wallets)
    matched = 0
    mismatched = 0
    errors = 0

    for w in wallets:
        try:
            results = await reconcile_wallet(w["id"])
            for r in results:
                if r.get("matches") is True:
                    matched += 1
                elif r.get("matches") is False:
                    mismatched += 1
                else:
                    errors += 1
        except Exception as e:
            errors += 1
            logger.error("reconciliation.wallet_error", wallet_id=str(w["id"]), error=str(e))

    summary = {
        "total_wallets": total,
        "checks_matched": matched,
        "checks_mismatched": mismatched,
        "checks_errored": errors,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    logger.info("reconciliation.complete", **summary)
    return summary


async def _fire_alert(run_result: Dict[str, Any]) -> None:
    """Send alert via webhook on reconciliation mismatch."""
    settings = get_settings()
    webhook_url = settings.reconciliation_alert_webhook

    if not webhook_url:
        logger.warning("reconciliation.no_webhook_configured")
        return

    payload = {
        "alert": "RECONCILIATION_MISMATCH",
        "severity": "critical",
        "data": run_result,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook_url, json=payload)
            logger.info(
                "reconciliation.alert_sent",
                status_code=resp.status_code,
                wallet_id=run_result.get("wallet_id"),
            )
    except Exception as e:
        logger.error("reconciliation.alert_failed", error=str(e))
