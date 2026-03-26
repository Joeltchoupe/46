"""
W46 Blockchain Factory — Returns the right chain client for a given rail.

Provides a unified ChainClient protocol and caches instances.
"""

from __future__ import annotations

import abc
from decimal import Decimal
from typing import Any, Dict, Optional, Protocol, runtime_checkable

import structlog

from w46.kms import KMSBase, KeyReference, get_kms
from w46.models import TxRail

logger = structlog.get_logger(__name__)


# ============================================================
# Unified Protocol
# ============================================================

@runtime_checkable
class ChainClient(Protocol):
    """Protocol that both SolanaClient and BaseClient implement."""

    async def get_usdc_balance(self, address: str) -> Decimal: ...

    async def transfer_usdc(
        self,
        from_key_ref: KeyReference,
        from_address: str,
        to_address: str,
        amount_usdc: Decimal,
    ) -> Dict[str, Any]: ...

    async def verify_transaction(self, tx_hash: str) -> Dict[str, Any]: ...

    async def health_check(self) -> Dict[str, Any]: ...


# ── Cached Instances ───────────────────────────────────────
_clients: Dict[str, ChainClient] = {}


def get_chain_client(rail: TxRail | str) -> ChainClient:
    """
    Get a chain client for the specified rail.
    
    Raises ValueError for internal/budget_auth rails (no blockchain involved).
    """
    rail_str = rail.value if isinstance(rail, TxRail) else rail

    if rail_str in ("internal", "budget_auth"):
        raise ValueError(f"Rail '{rail_str}' does not use a blockchain client")

    if rail_str in _clients:
        return _clients[rail_str]

    kms = get_kms()

    if rail_str == "solana":
        from w46.blockchain.solana import SolanaClient
        client = SolanaClient(kms)
    elif rail_str == "base":
        from w46.blockchain.base import BaseClient
        client = BaseClient(kms)
    else:
        raise ValueError(f"Unknown chain rail: {rail_str}")

    _clients[rail_str] = client
    logger.info("blockchain.client_created", rail=rail_str)
    return client


async def health_check_all() -> Dict[str, Any]:
    """Run health checks on all chain clients."""
    results = {}

    for rail in ("solana", "base"):
        try:
            client = get_chain_client(rail)
            results[rail] = await client.health_check()
        except Exception as e:
            results[rail] = {"chain": rail, "status": "error", "error": str(e)}

    return results


def reset_clients() -> None:
    """For testing."""
    _clients.clear()
