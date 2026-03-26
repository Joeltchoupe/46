"""
W46 Proof System — Cryptographic proof chain and Merkle tree anchoring.

Each settled transaction produces a proof bundle:
- SHA-256 hash of the record (tx_hash, rail, policy snapshot, amounts)
- Chained to the previous proof hash for that wallet
- Batched into Merkle trees
- Merkle root published on-chain (Base CommitmentRegistry + Solana memo)

If anyone modifies a historical DB record, the chain breaks → verify_chain detects it.
"""

from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

import asyncpg
import structlog

from w46 import db

logger = structlog.get_logger(__name__)


# ============================================================
# Proof Hash Computation
# ============================================================

def compute_proof_hash(
    tx_id: str,
    tx_hash: Optional[str],
    rail: str,
    amount_usdc: str,
    fee_usdc: str,
    from_wallet_id: str,
    to_address: str,
    policy_snapshot: Dict[str, Any],
    prev_proof_hash: str,
    settled_at: str,
) -> str:
    """
    Compute SHA-256 proof hash for a transaction record.
    
    Deterministic: same inputs → same hash, always.
    Includes the previous proof hash → creates a chain per wallet.
    """
    payload = json.dumps(
        {
            "tx_id": tx_id,
            "tx_hash": tx_hash,
            "rail": rail,
            "amount_usdc": amount_usdc,
            "fee_usdc": fee_usdc,
            "from_wallet_id": from_wallet_id,
            "to_address": to_address,
            "policy_snapshot": policy_snapshot,
            "prev_proof_hash": prev_proof_hash,
            "settled_at": settled_at,
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# Genesis proof hash — first transaction in every wallet's chain
GENESIS_PROOF_HASH = "0" * 64


async def get_last_proof_hash(
    conn: asyncpg.Connection,
    wallet_id: UUID,
) -> str:
    """Get the proof hash of the last settled transaction for this wallet."""
    row = await conn.fetchrow(
        """
        SELECT proof_hash 
        FROM transactions 
        WHERE from_wallet_id = $1 
          AND proof_hash IS NOT NULL 
        ORDER BY settled_at DESC NULLS LAST, created_at DESC 
        LIMIT 1
        """,
        wallet_id,
    )
    return row["proof_hash"] if row else GENESIS_PROOF_HASH


async def attach_proof(
    conn: asyncpg.Connection,
    tx_id: UUID,
    wallet_id: UUID,
    tx_hash: Optional[str],
    rail: str,
    amount_usdc: Decimal,
    fee_usdc: Decimal,
    to_address: str,
    policy_snapshot: Dict[str, Any],
    settled_at: datetime,
) -> str:
    """
    Compute and attach the proof hash to a settled transaction.
    Returns the computed proof hash.
    """
    prev_hash = await get_last_proof_hash(conn, wallet_id)

    proof_hash = compute_proof_hash(
        tx_id=str(tx_id),
        tx_hash=tx_hash,
        rail=rail,
        amount_usdc=str(amount_usdc),
        fee_usdc=str(fee_usdc),
        from_wallet_id=str(wallet_id),
        to_address=to_address,
        policy_snapshot=policy_snapshot,
        prev_proof_hash=prev_hash,
        settled_at=settled_at.isoformat(),
    )

    await conn.execute(
        """
        UPDATE transactions 
        SET proof_hash = $1, prev_proof_hash = $2 
        WHERE id = $3
        """,
        proof_hash,
        prev_hash,
        tx_id,
    )

    logger.debug(
        "proof.attached",
        tx_id=str(tx_id),
        wallet_id=str(wallet_id),
        proof_hash=proof_hash[:16] + "...",
    )

    return proof_hash


# ============================================================
# Proof Chain Verification
# ============================================================

async def verify_wallet_chain(wallet_id: UUID) -> Dict[str, Any]:
    """
    Verify the entire proof chain for a wallet.
    
    Recomputes every hash from genesis and checks linkage.
    Returns verification result with details.
    """
    pool = db.get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, tx_hash, rail, amount_usdc, fee_usdc, from_wallet_id,
                   to_address, policy_snapshot, proof_hash, prev_proof_hash, settled_at
            FROM transactions
            WHERE from_wallet_id = $1
              AND proof_hash IS NOT NULL
            ORDER BY settled_at ASC NULLS LAST, created_at ASC
            """,
            wallet_id,
        )

    if not rows:
        return {
            "wallet_id": str(wallet_id),
            "chain_valid": True,
            "records_checked": 0,
            "message": "No settled transactions with proofs",
        }

    expected_prev = GENESIS_PROOF_HASH
    broken_at = None

    for row in rows:
        # Check linkage
        if row["prev_proof_hash"] != expected_prev:
            broken_at = str(row["id"])
            break

        # Recompute hash
        policy = (
            json.loads(row["policy_snapshot"])
            if isinstance(row["policy_snapshot"], str)
            else (row["policy_snapshot"] or {})
        )

        recomputed = compute_proof_hash(
            tx_id=str(row["id"]),
            tx_hash=row["tx_hash"],
            rail=row["rail"],
            amount_usdc=str(row["amount_usdc"]),
            fee_usdc=str(row["fee_usdc"]),
            from_wallet_id=str(row["from_wallet_id"]),
            to_address=row["to_address"],
            policy_snapshot=policy,
            prev_proof_hash=row["prev_proof_hash"],
            settled_at=row["settled_at"].isoformat() if row["settled_at"] else "",
        )

        if recomputed != row["proof_hash"]:
            broken_at = str(row["id"])
            break

        expected_prev = row["proof_hash"]

    if broken_at:
        logger.error(
            "proof.chain_broken",
            wallet_id=str(wallet_id),
            broken_at=broken_at,
        )
        return {
            "wallet_id": str(wallet_id),
            "chain_valid": False,
            "records_checked": len(rows),
            "first_broken_at": broken_at,
            "message": f"Proof chain integrity violation at tx {broken_at}",
        }

    return {
        "wallet_id": str(wallet_id),
        "chain_valid": True,
        "records_checked": len(rows),
        "message": "Proof chain integrity verified",
    }


# ============================================================
# Merkle Tree
# ============================================================

def compute_merkle_root(hashes: List[str]) -> str:
    """
    Compute a Merkle root from a list of hex hash strings.
    
    Standard binary Merkle tree. If odd number of leaves, last is duplicated.
    """
    if not hashes:
        return GENESIS_PROOF_HASH

    if len(hashes) == 1:
        return hashes[0]

    # Convert to bytes
    nodes = [bytes.fromhex(h) for h in hashes]

    while len(nodes) > 1:
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])  # Duplicate last if odd

        next_level = []
        for i in range(0, len(nodes), 2):
            combined = nodes[i] + nodes[i + 1]
            parent = hashlib.sha256(combined).digest()
            next_level.append(parent)
        nodes = next_level

    return nodes[0].hex()


async def create_anchor_batch(
    conn: asyncpg.Connection,
    batch_size: int = 100,
) -> Optional[Dict[str, Any]]:
    """
    Create a Merkle tree batch from un-anchored settled transactions.
    
    Returns the batch metadata or None if no transactions to anchor.
    """
    # Get un-anchored settled transactions (those with proof_hash but not in any batch)
    rows = await conn.fetch(
        """
        SELECT t.id, t.proof_hash
        FROM transactions t
        LEFT JOIN anchor_batches ab ON t.id >= ab.first_tx_id AND t.id <= ab.last_tx_id
        WHERE t.proof_hash IS NOT NULL
          AND t.status = 'settled'
          AND ab.id IS NULL
        ORDER BY t.settled_at ASC
        LIMIT $1
        """,
        batch_size,
    )

    if not rows:
        return None

    proof_hashes = [row["proof_hash"] for row in rows]
    merkle_root = compute_merkle_root(proof_hashes)

    first_tx_id = rows[0]["id"]
    last_tx_id = rows[-1]["id"]

    batch_id = await conn.fetchval(
        """
        INSERT INTO anchor_batches (merkle_root, tx_count, first_tx_id, last_tx_id)
        VALUES ($1, $2, $3, $4)
        RETURNING id
        """,
        merkle_root,
        len(rows),
        first_tx_id,
        last_tx_id,
    )

    logger.info(
        "proof.batch_created",
        batch_id=str(batch_id),
        tx_count=len(rows),
        merkle_root=merkle_root[:16] + "...",
    )

    return {
        "batch_id": str(batch_id),
        "merkle_root": merkle_root,
        "tx_count": len(rows),
        "first_tx_id": str(first_tx_id),
        "last_tx_id": str(last_tx_id),
    }
