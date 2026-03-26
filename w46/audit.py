"""
W46 Audit Log — Immutable, hash-chained audit trail.

Every significant action is recorded with a cryptographic hash linking
to the previous entry. PostgreSQL triggers prevent UPDATE/DELETE.

The hash chain allows detection of any tampering with historical records.
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

logger = structlog.get_logger(__name__)

# Cache for the last hash per scope to avoid DB lookups on every insert
_last_hash_cache: Dict[str, str] = {}

# Genesis hash — first entry in every chain
GENESIS_HASH = "0" * 64


def _compute_record_hash(
    action: str,
    actor: str,
    details: Dict[str, Any],
    prev_hash: str,
    created_at: str,
) -> str:
    """
    Compute SHA-256 hash of an audit record.
    Deterministic: same inputs always produce the same hash.
    """
    payload = json.dumps(
        {
            "action": action,
            "actor": actor,
            "details": details,
            "prev_hash": prev_hash,
            "created_at": created_at,
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _scope_key(org_id: Optional[str] = None) -> str:
    """Audit chains are scoped per organization (or global if no org)."""
    return f"org:{org_id}" if org_id else "global"


async def _get_last_hash(
    conn: asyncpg.Connection,
    org_id: Optional[UUID] = None,
) -> str:
    """Get the hash of the most recent audit entry for this scope."""
    scope = _scope_key(str(org_id) if org_id else None)

    # Check cache first
    if scope in _last_hash_cache:
        return _last_hash_cache[scope]

    # Query DB
    if org_id:
        row = await conn.fetchrow(
            "SELECT record_hash FROM audit_log WHERE org_id = $1 ORDER BY id DESC LIMIT 1",
            org_id,
        )
    else:
        row = await conn.fetchrow(
            "SELECT record_hash FROM audit_log WHERE org_id IS NULL ORDER BY id DESC LIMIT 1",
        )

    last = row["record_hash"] if row else GENESIS_HASH
    _last_hash_cache[scope] = last
    return last


async def log(
    action: str,
    actor: str,
    *,
    org_id: Optional[UUID] = None,
    wallet_id: Optional[UUID] = None,
    tx_id: Optional[UUID] = None,
    details: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None,
    conn: Optional[asyncpg.Connection] = None,
) -> int:
    """
    Record an immutable audit entry with hash chaining.
    
    Returns the audit log entry ID.
    """
    details = details or {}
    now = datetime.now(timezone.utc).isoformat()

    async def _do_insert(c: asyncpg.Connection) -> int:
        prev_hash = await _get_last_hash(c, org_id)
        record_hash = _compute_record_hash(action, actor, details, prev_hash, now)

        entry_id = await c.fetchval(
            """
            INSERT INTO audit_log 
                (org_id, wallet_id, tx_id, action, actor, details, ip_address, record_hash, prev_hash)
            VALUES ($1, $2, $3, $4::audit_action, $5, $6::jsonb, $7::inet, $8, $9)
            RETURNING id
            """,
            org_id,
            wallet_id,
            tx_id,
            action,
            actor,
            json.dumps(details, default=str),
            ip_address,
            record_hash,
            prev_hash,
        )

        # Update cache
        scope = _scope_key(str(org_id) if org_id else None)
        _last_hash_cache[scope] = record_hash

        logger.info(
            "audit.logged",
            action=action,
            actor=actor,
            org_id=str(org_id) if org_id else None,
            wallet_id=str(wallet_id) if wallet_id else None,
            entry_id=entry_id,
        )
        return entry_id

    if conn:
        return await _do_insert(conn)

    pool = db.get_pool()
    async with pool.acquire() as c:
        return await _do_insert(c)


async def verify_chain(
    org_id: Optional[UUID] = None,
    limit: int = 10000,
) -> Dict[str, Any]:
    """
    Verify the integrity of the audit hash chain for an organization.
    
    Returns verification result with details on any broken links.
    """
    pool = db.get_pool()
    async with pool.acquire() as conn:
        if org_id:
            rows = await conn.fetch(
                """
                SELECT id, action, actor, details, record_hash, prev_hash, created_at
                FROM audit_log 
                WHERE org_id = $1 
                ORDER BY id ASC 
                LIMIT $2
                """,
                org_id,
                limit,
            )
        else:
            rows = await conn.fetch(
                """
                SELECT id, action, actor, details, record_hash, prev_hash, created_at
                FROM audit_log 
                WHERE org_id IS NULL 
                ORDER BY id ASC 
                LIMIT $1
                """,
                limit,
            )

    if not rows:
        return {
            "valid": True,
            "records_checked": 0,
            "message": "No audit records found",
        }

    # Verify chain
    expected_prev = GENESIS_HASH
    broken_at = None

    for row in rows:
        # Check prev_hash linkage
        if row["prev_hash"] != expected_prev:
            broken_at = row["id"]
            break

        # Recompute hash and verify
        details = json.loads(row["details"]) if isinstance(row["details"], str) else row["details"]
        recomputed = _compute_record_hash(
            row["action"],
            row["actor"],
            details,
            row["prev_hash"],
            row["created_at"].isoformat() if hasattr(row["created_at"], "isoformat") else str(row["created_at"]),
        )

        if recomputed != row["record_hash"]:
            broken_at = row["id"]
            break

        expected_prev = row["record_hash"]

    if broken_at:
        logger.error("audit.chain_broken", org_id=str(org_id), broken_at=broken_at)
        return {
            "valid": False,
            "records_checked": len(rows),
            "broken_at_id": broken_at,
            "message": f"Hash chain integrity violation at audit entry {broken_at}",
        }

    return {
        "valid": True,
        "records_checked": len(rows),
        "message": "Audit chain integrity verified",
    }


def clear_cache() -> None:
    """Clear the last-hash cache. For testing."""
    _last_hash_cache.clear()
