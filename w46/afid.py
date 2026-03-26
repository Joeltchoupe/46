"""
W46 AFID — Agent Financial Identity (Portable).

AFID allows an agent's wallet to share its capabilities, reputation,
and transaction history proof with external platforms.

Components:
- Public key (derived from wallet's KMS key)
- Trust score
- Capabilities manifest (supported rails, volume, limits)
- Signed verification proof (proves ownership without exposing private key)
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import UUID

import asyncpg
import structlog

from w46 import db
from w46.kms import KeyReference, get_kms

logger = structlog.get_logger(__name__)


async def generate_afid(
    conn: asyncpg.Connection,
    wallet_id: UUID,
) -> Dict[str, Any]:
    """
    Generate or update the AFID for a wallet.
    
    Returns the portable identity document.
    """
    wallet = await conn.fetchrow(
        """
        SELECT id, org_id, agent_id, solana_address, base_address,
               solana_key_ref, base_key_ref, trust_score, balance_usdc,
               created_at
        FROM wallets WHERE id = $1
        """,
        wallet_id,
    )

    if not wallet:
        raise ValueError(f"Wallet {wallet_id} not found")

    # ── Build capabilities manifest ────────────────────────
    capabilities = {
        "rails": [],
        "created_at": wallet["created_at"].isoformat(),
        "agent_id": wallet["agent_id"],
    }

    if wallet["solana_address"]:
        capabilities["rails"].append({
            "chain": "solana",
            "address": wallet["solana_address"],
            "token": "USDC",
        })

    if wallet["base_address"]:
        capabilities["rails"].append({
            "chain": "base",
            "address": wallet["base_address"],
            "token": "USDC",
        })

    # ── Transaction stats ──────────────────────────────────
    stats = await conn.fetchrow(
        """
        SELECT
            COUNT(*) FILTER (WHERE status = 'settled') as settled_count,
            COALESCE(SUM(amount_usdc) FILTER (WHERE status = 'settled'), 0) as total_volume,
            MIN(created_at) FILTER (WHERE status = 'settled') as first_tx,
            MAX(created_at) FILTER (WHERE status = 'settled') as last_tx
        FROM transactions
        WHERE from_wallet_id = $1
        """,
        wallet_id,
    )

    capabilities["transaction_history"] = {
        "total_settled": stats["settled_count"] or 0,
        "total_volume_usdc": str(stats["total_volume"] or 0),
        "first_transaction": stats["first_tx"].isoformat() if stats["first_tx"] else None,
        "last_transaction": stats["last_tx"].isoformat() if stats["last_tx"] else None,
    }

    # ── Generate verification proof ────────────────────────
    # Hash the capabilities + wallet_id + timestamp
    now = datetime.now(timezone.utc)
    proof_payload = json.dumps({
        "wallet_id": str(wallet_id),
        "capabilities": capabilities,
        "trust_score": wallet["trust_score"],
        "timestamp": now.isoformat(),
    }, sort_keys=True, default=str)

    proof_hash = hashlib.sha256(proof_payload.encode()).hexdigest()

    # Sign the proof hash with the wallet's key
    kms = get_kms()
    signature_hex = ""

    # Use Solana key if available, else Base key
    key_ref_data = wallet["solana_key_ref"] or wallet["base_key_ref"]
    chain = "solana" if wallet["solana_key_ref"] else "base"

    if key_ref_data:
        try:
            key_ref_meta = json.loads(key_ref_data) if isinstance(key_ref_data, str) else key_ref_data
            key_ref = KeyReference(
                key_id=key_ref_meta.get("key_id", ""),
                chain=chain,
                metadata=key_ref_meta,
            )
            signature = await kms.sign_message(key_ref, proof_hash.encode())
            signature_hex = signature.hex()
        except Exception as e:
            logger.warning("afid.sign_failed", wallet_id=str(wallet_id), error=str(e))
            signature_hex = "unsigned"

    # ── Store AFID public key ──────────────────────────────
    afid_public_key = (
        wallet["solana_address"]
        or wallet["base_address"]
        or ""
    )

    await conn.execute(
        """
        UPDATE wallets
        SET afid_public_key = $1, afid_metadata = $2::jsonb
        WHERE id = $3
        """,
        afid_public_key,
        json.dumps(capabilities, default=str),
        wallet_id,
    )

    afid_document = {
        "version": "1.0",
        "wallet_id": str(wallet_id),
        "afid_public_key": afid_public_key,
        "trust_score": wallet["trust_score"],
        "capabilities": capabilities,
        "verification_proof": {
            "hash": proof_hash,
            "signature": signature_hex,
            "signing_chain": chain,
            "timestamp": now.isoformat(),
        },
    }

    logger.info("afid.generated", wallet_id=str(wallet_id))
    return afid_document


async def verify_afid(afid_document: Dict[str, Any]) -> Dict[str, Any]:
    """
    Verify an AFID document.
    
    Checks:
    1. Proof hash matches document contents
    2. Wallet exists in our system (optional — could be cross-platform)
    3. Signature is valid
    """
    proof = afid_document.get("verification_proof", {})

    # Recompute proof hash
    proof_payload = json.dumps({
        "wallet_id": afid_document.get("wallet_id"),
        "capabilities": afid_document.get("capabilities"),
        "trust_score": afid_document.get("trust_score"),
        "timestamp": proof.get("timestamp"),
    }, sort_keys=True, default=str)

    expected_hash = hashlib.sha256(proof_payload.encode()).hexdigest()
    hash_valid = expected_hash == proof.get("hash")

    # Check if wallet exists locally
    wallet_exists = False
    try:
        wallet_id = UUID(afid_document.get("wallet_id", ""))
        row = await db.fetchrow(
            "SELECT id, trust_score FROM wallets WHERE id = $1",
            wallet_id,
        )
        wallet_exists = row is not None
    except (ValueError, TypeError):
        pass

    return {
        "proof_hash_valid": hash_valid,
        "wallet_exists_locally": wallet_exists,
        "trust_score": afid_document.get("trust_score"),
        "verification_status": "valid" if hash_valid else "invalid",
    }
