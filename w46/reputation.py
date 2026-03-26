"""
W46 Reputation Engine — Trust score 0-100 per wallet.

Components (weighted):
- Settlement rate:    What % of initiated tx actually settle?     (weight: 30)
- Policy compliance:  What % pass policy on first try?            (weight: 25)
- Volume maturity:    Normalized lifetime USDC volume              (weight: 20)
- Account age:        Days since wallet creation, capped           (weight: 15)
- Incident history:   Reconciliation mismatches, frozen events     (weight: 10, penalty)

Score is recalculated periodically and on significant events.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, Optional
from uuid import UUID

import asyncpg
import structlog

from w46 import db, audit

logger = structlog.get_logger(__name__)

# ── Weight Configuration ───────────────────────────────────
WEIGHT_SETTLEMENT_RATE = 30
WEIGHT_POLICY_COMPLIANCE = 25
WEIGHT_VOLUME_MATURITY = 20
WEIGHT_ACCOUNT_AGE = 15
WEIGHT_INCIDENT_PENALTY = 10

# ── Normalization Constants ────────────────────────────────
VOLUME_MATURITY_CAP_USDC = Decimal("1000000")   # 1M USDC = max maturity
AGE_CAP_DAYS = 365                                # 1 year = max age score
INCIDENT_PENALTY_PER_EVENT = 5                     # -5 per incident, capped at weight


async def calculate_trust_score(
    conn: asyncpg.Connection,
    wallet_id: UUID,
) -> Dict[str, Any]:
    """
    Calculate trust score for a wallet.
    
    Returns:
        {
            "trust_score": int (0-100),
            "components": { ... breakdown ... }
        }
    """
    now = datetime.now(timezone.utc)

    # ── Fetch wallet creation date ─────────────────────────
    wallet = await conn.fetchrow(
        "SELECT created_at FROM wallets WHERE id = $1",
        wallet_id,
    )
    if not wallet:
        return {"trust_score": 0, "components": {"error": "wallet not found"}}

    age_days = (now - wallet["created_at"].replace(tzinfo=timezone.utc)).days

    # ── Transaction stats ──────────────────────────────────
    stats = await conn.fetchrow(
        """
        SELECT
            COUNT(*) FILTER (WHERE status != 'pending_policy') AS total_initiated,
            COUNT(*) FILTER (WHERE status = 'settled') AS total_settled,
            COUNT(*) FILTER (WHERE status = 'policy_rejected') AS total_rejected,
            COUNT(*) FILTER (WHERE status = 'failed') AS total_failed,
            COALESCE(SUM(amount_usdc) FILTER (WHERE status = 'settled'), 0) AS total_volume
        FROM transactions
        WHERE from_wallet_id = $1
        """,
        wallet_id,
    )

    total_initiated = stats["total_initiated"] or 0
    total_settled = stats["total_settled"] or 0
    total_rejected = stats["total_rejected"] or 0
    total_volume = stats["total_volume"] or Decimal("0")

    # ── Incident count ─────────────────────────────────────
    incidents = await conn.fetchval(
        """
        SELECT COUNT(*) FROM reconciliation_runs
        WHERE wallet_id = $1 AND matches = FALSE
        """,
        wallet_id,
    ) or 0

    freeze_incidents = await conn.fetchval(
        """
        SELECT COUNT(*) FROM audit_log
        WHERE wallet_id = $1 AND action = 'wallet_frozen'
        """,
        wallet_id,
    ) or 0

    total_incidents = incidents + freeze_incidents

    # ── Component Calculations ─────────────────────────────

    # 1. Settlement Rate (0-100, then weighted)
    if total_initiated > 0:
        settlement_rate = (total_settled / total_initiated) * 100
    else:
        settlement_rate = 50.0  # Neutral for new wallets

    # 2. Policy Compliance (0-100)
    total_policy_checked = total_settled + total_rejected
    if total_policy_checked > 0:
        policy_compliance = ((total_policy_checked - total_rejected) / total_policy_checked) * 100
    else:
        policy_compliance = 50.0

    # 3. Volume Maturity (0-100, logarithmic scale)
    if total_volume > 0:
        # Log scale: $1 → ~0, $1M → 100
        volume_ratio = float(min(total_volume, VOLUME_MATURITY_CAP_USDC) / VOLUME_MATURITY_CAP_USDC)
        volume_maturity = min(100.0, (math.log10(volume_ratio * 999 + 1) / 3) * 100) if volume_ratio > 0 else 0
    else:
        volume_maturity = 0.0

    # 4. Account Age (0-100, linear capped)
    age_score = min(100.0, (age_days / AGE_CAP_DAYS) * 100)

    # 5. Incident Penalty (0-100, subtracted)
    incident_penalty = min(100.0, total_incidents * INCIDENT_PENALTY_PER_EVENT)

    # ── Weighted Score ─────────────────────────────────────
    raw_score = (
        (settlement_rate / 100) * WEIGHT_SETTLEMENT_RATE
        + (policy_compliance / 100) * WEIGHT_POLICY_COMPLIANCE
        + (volume_maturity / 100) * WEIGHT_VOLUME_MATURITY
        + (age_score / 100) * WEIGHT_ACCOUNT_AGE
        - (incident_penalty / 100) * WEIGHT_INCIDENT_PENALTY
    )

    trust_score = max(0, min(100, int(round(raw_score))))

    components = {
        "settlement_rate": {
            "value": round(settlement_rate, 2),
            "weight": WEIGHT_SETTLEMENT_RATE,
            "total_initiated": total_initiated,
            "total_settled": total_settled,
        },
        "policy_compliance": {
            "value": round(policy_compliance, 2),
            "weight": WEIGHT_POLICY_COMPLIANCE,
            "total_checked": total_policy_checked,
            "total_rejected": total_rejected,
        },
        "volume_maturity": {
            "value": round(volume_maturity, 2),
            "weight": WEIGHT_VOLUME_MATURITY,
            "total_volume_usdc": str(total_volume),
        },
        "account_age": {
            "value": round(age_score, 2),
            "weight": WEIGHT_ACCOUNT_AGE,
            "age_days": age_days,
        },
        "incident_penalty": {
            "value": round(incident_penalty, 2),
            "weight": WEIGHT_INCIDENT_PENALTY,
            "total_incidents": total_incidents,
        },
    }

    logger.info(
        "reputation.calculated",
        wallet_id=str(wallet_id),
        trust_score=trust_score,
    )

    return {
        "trust_score": trust_score,
        "components": components,
    }


async def update_trust_score(wallet_id: UUID) -> int:
    """Recalculate and persist the trust score for a wallet."""
    pool = db.get_pool()
    async with pool.acquire() as conn:
        result = await calculate_trust_score(conn, wallet_id)
        score = result["trust_score"]

        await conn.execute(
            "UPDATE wallets SET trust_score = $1 WHERE id = $2",
            score,
            wallet_id,
        )

        await audit.log(
            "reputation_updated",
            "system",
            wallet_id=wallet_id,
            details={"trust_score": score, "components": result["components"]},
            conn=conn,
        )

        return score
