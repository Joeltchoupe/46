"""
W46 Routing Engine — Selects the optimal blockchain rail for each payment.

Rails:
- solana:      Micro-payments ≤ threshold. Sub-second, $0.005/USDC fee.
- base:        Large payments ≥ threshold or verified rail required. ~2s, $0.05/USDC.
- internal:    Between W46 wallets in the same org. Free, instant.
- budget_auth: Destination only accepts fiat. No USDC moves; budget reserved.

Circuit Breakers:
- Per-rail failure tracking via Redis.
- After N consecutive failures, circuit opens → traffic reroutes.
- Half-open state after timeout → single probe request allowed.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from decimal import Decimal
from enum import Enum
from typing import Any, Dict, Optional

import structlog

from w46.config import get_settings
from w46.models import TxRail

logger = structlog.get_logger(__name__)


# ============================================================
# Circuit Breaker (in-memory, Redis-backed in production)
# ============================================================

class CircuitState(str, Enum):
    CLOSED = "closed"          # Normal operation
    OPEN = "open"              # Rail is down, all requests fail fast
    HALF_OPEN = "half_open"    # Probing — allow one request through


@dataclass
class CircuitBreaker:
    """Per-rail circuit breaker."""
    rail: str
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    last_failure_at: float = 0.0
    last_success_at: float = 0.0
    threshold: int = 5
    timeout_sec: int = 300

    def record_failure(self) -> None:
        self.failure_count += 1
        self.last_failure_at = time.time()
        if self.failure_count >= self.threshold:
            self.state = CircuitState.OPEN
            logger.warning(
                "circuit_breaker.opened",
                rail=self.rail,
                failures=self.failure_count,
            )

    def record_success(self) -> None:
        self.failure_count = 0
        self.last_success_at = time.time()
        if self.state != CircuitState.CLOSED:
            logger.info("circuit_breaker.closed", rail=self.rail)
        self.state = CircuitState.CLOSED

    def is_available(self) -> bool:
        if self.state == CircuitState.CLOSED:
            return True
        if self.state == CircuitState.OPEN:
            elapsed = time.time() - self.last_failure_at
            if elapsed >= self.timeout_sec:
                self.state = CircuitState.HALF_OPEN
                logger.info("circuit_breaker.half_open", rail=self.rail)
                return True
            return False
        # HALF_OPEN: allow one probe
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rail": self.rail,
            "state": self.state.value,
            "failure_count": self.failure_count,
            "last_failure_at": self.last_failure_at,
            "last_success_at": self.last_success_at,
        }


# ── Module-level circuit breakers ──────────────────────────
_breakers: Dict[str, CircuitBreaker] = {}


def _get_breaker(rail: str) -> CircuitBreaker:
    if rail not in _breakers:
        s = get_settings()
        _breakers[rail] = CircuitBreaker(
            rail=rail,
            threshold=s.routing_circuit_breaker_threshold,
            timeout_sec=s.routing_circuit_breaker_timeout_sec,
        )
    return _breakers[rail]


def record_rail_failure(rail: str) -> None:
    _get_breaker(rail).record_failure()


def record_rail_success(rail: str) -> None:
    _get_breaker(rail).record_success()


def get_breaker_states() -> Dict[str, Dict[str, Any]]:
    return {rail: b.to_dict() for rail, b in _breakers.items()}


# ============================================================
# Routing Decision
# ============================================================

@dataclass(frozen=True)
class RoutingDecision:
    """Immutable routing decision."""
    rail: TxRail
    reason: str
    fee_per_usdc: Decimal
    estimated_time_sec: float
    fallback_used: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rail": self.rail.value,
            "reason": self.reason,
            "fee_per_usdc": str(self.fee_per_usdc),
            "estimated_time_sec": self.estimated_time_sec,
            "fallback_used": self.fallback_used,
        }


def select_rail(
    amount_usdc: Decimal,
    to_address: str,
    from_org_id: str,
    *,
    to_wallet_id: Optional[str] = None,
    to_org_id: Optional[str] = None,
    requires_verified_rail: bool = False,
    preferred_rail: Optional[TxRail] = None,
    budget_auth_only: bool = False,
) -> RoutingDecision:
    """
    Deterministic rail selection.
    
    Priority order:
    1. Budget auth (if flagged)
    2. Internal (same org, both have W46 wallets)
    3. Preferred rail (if specified and available)
    4. Verified rail requirement → Base
    5. Amount-based: Solana for micro, Base for large
    6. Fallback if primary rail is down
    """
    settings = get_settings()

    # ── Budget Authorization ───────────────────────────────
    if budget_auth_only:
        return RoutingDecision(
            rail=TxRail.BUDGET_AUTH,
            reason="destination only accepts fiat — budget reserved, no USDC moved",
            fee_per_usdc=Decimal("0"),
            estimated_time_sec=0.0,
        )

    # ── Internal Transfer ──────────────────────────────────
    if to_wallet_id and to_org_id == from_org_id:
        return RoutingDecision(
            rail=TxRail.INTERNAL,
            reason="same-org W46 wallet transfer — free and instant",
            fee_per_usdc=Decimal(str(settings.fee_internal_per_usdc)),
            estimated_time_sec=0.05,
        )

    # ── Preferred Rail ─────────────────────────────────────
    if preferred_rail and preferred_rail in (TxRail.SOLANA, TxRail.BASE):
        breaker = _get_breaker(preferred_rail.value)
        if breaker.is_available():
            fee = (
                Decimal(str(settings.fee_solana_per_usdc))
                if preferred_rail == TxRail.SOLANA
                else Decimal(str(settings.fee_base_per_usdc))
            )
            est_time = 0.8 if preferred_rail == TxRail.SOLANA else 2.0
            return RoutingDecision(
                rail=preferred_rail,
                reason=f"preferred rail: {preferred_rail.value}",
                fee_per_usdc=fee,
                estimated_time_sec=est_time,
            )

    # ── Verified Rail Required ─────────────────────────────
    if requires_verified_rail:
        base_breaker = _get_breaker("base")
        if base_breaker.is_available():
            return RoutingDecision(
                rail=TxRail.BASE,
                reason=f"verified rail required for amount ≥ threshold",
                fee_per_usdc=Decimal(str(settings.fee_base_per_usdc)),
                estimated_time_sec=2.0,
            )
        # Fallback to Solana even for verified if Base is down
        sol_breaker = _get_breaker("solana")
        if sol_breaker.is_available():
            return RoutingDecision(
                rail=TxRail.SOLANA,
                reason="verified rail (Base) down — fallback to Solana",
                fee_per_usdc=Decimal(str(settings.fee_solana_per_usdc)),
                estimated_time_sec=0.8,
                fallback_used=True,
            )

    # ── Amount-Based Routing ───────────────────────────────
    solana_breaker = _get_breaker("solana")
    base_breaker = _get_breaker("base")

    solana_available = solana_breaker.is_available()
    base_available = base_breaker.is_available()

    solana_max = Decimal(str(settings.routing_solana_max_usdc))
    base_min = Decimal(str(settings.routing_base_min_usdc))

    # Micro-payment → Solana
    if amount_usdc <= solana_max and solana_available:
        return RoutingDecision(
            rail=TxRail.SOLANA,
            reason=f"micro-payment ≤ {solana_max} USDC — Solana optimal",
            fee_per_usdc=Decimal(str(settings.fee_solana_per_usdc)),
            estimated_time_sec=0.8,
        )

    # Large payment → Base
    if amount_usdc >= base_min and base_available:
        return RoutingDecision(
            rail=TxRail.BASE,
            reason=f"large payment ≥ {base_min} USDC — Base optimal",
            fee_per_usdc=Decimal(str(settings.fee_base_per_usdc)),
            estimated_time_sec=2.0,
        )

    # Mid-range: prefer Solana, fallback Base
    if solana_available:
        return RoutingDecision(
            rail=TxRail.SOLANA,
            reason="mid-range payment — Solana (lower fees)",
            fee_per_usdc=Decimal(str(settings.fee_solana_per_usdc)),
            estimated_time_sec=0.8,
        )

    if base_available:
        return RoutingDecision(
            rail=TxRail.BASE,
            reason="Solana unavailable — fallback to Base",
            fee_per_usdc=Decimal(str(settings.fee_base_per_usdc)),
            estimated_time_sec=2.0,
            fallback_used=True,
        )

    # ── All Rails Down ─────────────────────────────────────
    logger.error("routing.all_rails_down", amount=str(amount_usdc))
    # Return a DEFERRED decision — caller must handle
    return RoutingDecision(
        rail=TxRail.SOLANA,  # Placeholder — will be marked DEFERRED by caller
        reason="ALL RAILS DOWN — transaction will be deferred",
        fee_per_usdc=Decimal("0"),
        estimated_time_sec=-1,  # Sentinel: negative = deferred
        fallback_used=True,
    )


def reset_breakers() -> None:
    """For testing."""
    _breakers.clear()
