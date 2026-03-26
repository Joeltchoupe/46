"""
W46 Policy Engine — Deterministic, pre-transaction rule evaluation.

If the policy refuses, NOTHING happens: no blockchain tx, no gas, no fees.

Rules evaluated (in order):
1. Wallet status (must be active)
2. Amount per transaction
3. Daily spending limit
4. Monthly spending limit
5. Allowed categories (whitelist if non-empty)
6. Blocked destinations (blacklist)
7. Memo requirement
8. Human approval threshold
9. Verified rail threshold

All checks are DETERMINISTIC — same inputs = same output, always.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date
from decimal import Decimal
from typing import Any, Dict, List, Optional
from uuid import UUID

import asyncpg
import structlog

from w46 import db
from w46.exceptions import (
    HumanApprovalRequiredError,
    PolicyViolationError,
    WalletFrozenError,
    WalletClosedError,
)

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class PolicySnapshot:
    """Immutable snapshot of the policy at evaluation time. Stored with the tx."""
    max_per_tx_usdc: Decimal
    daily_limit_usdc: Decimal
    monthly_limit_usdc: Decimal
    allowed_categories: List[str]
    blocked_destinations: List[str]
    human_approval_threshold: Decimal
    verified_rail_threshold: Decimal
    require_memo: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "max_per_tx_usdc": str(self.max_per_tx_usdc),
            "daily_limit_usdc": str(self.daily_limit_usdc),
            "monthly_limit_usdc": str(self.monthly_limit_usdc),
            "allowed_categories": self.allowed_categories,
            "blocked_destinations": self.blocked_destinations,
            "human_approval_threshold": str(self.human_approval_threshold),
            "verified_rail_threshold": str(self.verified_rail_threshold),
            "require_memo": self.require_memo,
        }


@dataclass
class PolicyResult:
    """Result of policy evaluation."""
    approved: bool
    reason: str
    requires_human_approval: bool = False
    requires_verified_rail: bool = False
    checks: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "approved": self.approved,
            "reason": self.reason,
            "requires_human_approval": self.requires_human_approval,
            "requires_verified_rail": self.requires_verified_rail,
            "checks": self.checks,
        }


@dataclass
class PaymentContext:
    """All inputs needed for policy evaluation."""
    wallet_id: UUID
    wallet_status: str
    amount_usdc: Decimal
    to_address: str
    category: Optional[str]
    memo: Optional[str]
    daily_spent: Decimal
    monthly_spent: Decimal
    daily_reset_at: date
    monthly_reset_at: date


async def load_policy_snapshot(
    conn: asyncpg.Connection,
    wallet_id: UUID,
) -> PolicySnapshot:
    """Load the active policy for a wallet, or create a default one."""
    from w46.config import get_settings

    row = await conn.fetchrow(
        """
        SELECT max_per_tx_usdc, daily_limit_usdc, monthly_limit_usdc,
               allowed_categories, blocked_destinations,
               human_approval_threshold, verified_rail_threshold, require_memo
        FROM policies
        WHERE wallet_id = $1 AND is_active = TRUE
        ORDER BY created_at DESC
        LIMIT 1
        """,
        wallet_id,
    )

    if row:
        return PolicySnapshot(
            max_per_tx_usdc=row["max_per_tx_usdc"],
            daily_limit_usdc=row["daily_limit_usdc"],
            monthly_limit_usdc=row["monthly_limit_usdc"],
            allowed_categories=list(row["allowed_categories"] or []),
            blocked_destinations=list(row["blocked_destinations"] or []),
            human_approval_threshold=row["human_approval_threshold"],
            verified_rail_threshold=row["verified_rail_threshold"],
            require_memo=row["require_memo"],
        )

    # Return defaults from config
    s = get_settings()
    return PolicySnapshot(
        max_per_tx_usdc=Decimal(str(s.policy_default_max_per_tx)),
        daily_limit_usdc=Decimal(str(s.policy_default_daily_limit)),
        monthly_limit_usdc=Decimal(str(s.policy_default_monthly_limit)),
        allowed_categories=[],
        blocked_destinations=[],
        human_approval_threshold=Decimal(str(s.policy_default_human_approval_threshold)),
        verified_rail_threshold=Decimal(str(s.policy_default_verified_rail_threshold)),
        require_memo=False,
    )


def evaluate(ctx: PaymentContext, policy: PolicySnapshot) -> PolicyResult:
    """
    Deterministic policy evaluation.
    
    Runs ALL checks and collects results. Fails fast on hard rejections
    but still records all checks for the audit trail.
    """
    checks: List[Dict[str, Any]] = []
    approved = True
    reason = "all checks passed"
    requires_human = False
    requires_verified = False

    # Adjust daily/monthly spent for counter resets
    today = date.today()
    effective_daily = ctx.daily_spent if ctx.daily_reset_at >= today else Decimal("0")
    effective_monthly = ctx.monthly_spent if ctx.monthly_reset_at >= today.replace(day=1) else Decimal("0")

    # ── Check 1: Wallet Status ─────────────────────────────
    status_ok = ctx.wallet_status == "active"
    checks.append({
        "check": "wallet_status",
        "passed": status_ok,
        "actual": ctx.wallet_status,
        "required": "active",
    })
    if not status_ok:
        approved = False
        reason = f"wallet is {ctx.wallet_status}"

    # ── Check 2: Amount per TX ─────────────────────────────
    amount_ok = ctx.amount_usdc <= policy.max_per_tx_usdc
    checks.append({
        "check": "max_per_tx",
        "passed": amount_ok,
        "actual": str(ctx.amount_usdc),
        "limit": str(policy.max_per_tx_usdc),
    })
    if not amount_ok:
        approved = False
        reason = f"amount {ctx.amount_usdc} exceeds per-tx limit {policy.max_per_tx_usdc}"

    # ── Check 3: Daily Limit ──────────────────────────────
    projected_daily = effective_daily + ctx.amount_usdc
    daily_ok = projected_daily <= policy.daily_limit_usdc
    checks.append({
        "check": "daily_limit",
        "passed": daily_ok,
        "current_spent": str(effective_daily),
        "projected": str(projected_daily),
        "limit": str(policy.daily_limit_usdc),
    })
    if not daily_ok:
        approved = False
        reason = f"daily limit exceeded: {projected_daily} > {policy.daily_limit_usdc}"

    # ── Check 4: Monthly Limit ─────────────────────────────
    projected_monthly = effective_monthly + ctx.amount_usdc
    monthly_ok = projected_monthly <= policy.monthly_limit_usdc
    checks.append({
        "check": "monthly_limit",
        "passed": monthly_ok,
        "current_spent": str(effective_monthly),
        "projected": str(projected_monthly),
        "limit": str(policy.monthly_limit_usdc),
    })
    if not monthly_ok:
        approved = False
        reason = f"monthly limit exceeded: {projected_monthly} > {policy.monthly_limit_usdc}"

    # ── Check 5: Allowed Categories ────────────────────────
    if policy.allowed_categories:
        cat_ok = ctx.category in policy.allowed_categories if ctx.category else False
        checks.append({
            "check": "allowed_categories",
            "passed": cat_ok,
            "actual": ctx.category,
            "allowed": policy.allowed_categories,
        })
        if not cat_ok:
            approved = False
            reason = f"category '{ctx.category}' not in allowed list"
    else:
        checks.append({"check": "allowed_categories", "passed": True, "note": "no whitelist"})

    # ── Check 6: Blocked Destinations ──────────────────────
    dest_blocked = ctx.to_address in policy.blocked_destinations
    checks.append({
        "check": "blocked_destinations",
        "passed": not dest_blocked,
        "address": ctx.to_address,
    })
    if dest_blocked:
        approved = False
        reason = f"destination {ctx.to_address} is blocked"

    # ── Check 7: Memo Requirement ──────────────────────────
    if policy.require_memo:
        memo_ok = bool(ctx.memo and ctx.memo.strip())
        checks.append({"check": "require_memo", "passed": memo_ok})
        if not memo_ok:
            approved = False
            reason = "memo is required but missing"
    else:
        checks.append({"check": "require_memo", "passed": True, "note": "not required"})

    # ── Check 8: Human Approval Threshold ──────────────────
    if ctx.amount_usdc >= policy.human_approval_threshold:
        requires_human = True
        checks.append({
            "check": "human_approval_threshold",
            "triggered": True,
            "amount": str(ctx.amount_usdc),
            "threshold": str(policy.human_approval_threshold),
        })

    # ── Check 9: Verified Rail Threshold ───────────────────
    if ctx.amount_usdc >= policy.verified_rail_threshold:
        requires_verified = True
        checks.append({
            "check": "verified_rail_threshold",
            "triggered": True,
            "amount": str(ctx.amount_usdc),
            "threshold": str(policy.verified_rail_threshold),
        })

    result = PolicyResult(
        approved=approved,
        reason=reason,
        requires_human_approval=requires_human,
        requires_verified_rail=requires_verified,
        checks=checks,
    )

    logger.info(
        "policy.evaluated",
        wallet_id=str(ctx.wallet_id),
        amount=str(ctx.amount_usdc),
        approved=approved,
        reason=reason,
        requires_human=requires_human,
    )

    return result
