"""
W46 Database — Async connection pool with advisory locks and health checks.

Uses asyncpg for high-performance async PostgreSQL access.
Advisory locks are per-wallet to prevent race conditions on balance updates.
"""

from __future__ import annotations

import hashlib
import struct
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Dict, List, Optional

import asyncpg
import structlog

from w46.config import get_settings

logger = structlog.get_logger(__name__)

# ── Module State ───────────────────────────────────────────
_pool: Optional[asyncpg.Pool] = None


async def init_pool() -> asyncpg.Pool:
    """Initialize the connection pool. Call once at startup."""
    global _pool
    if _pool is not None:
        return _pool

    settings = get_settings()
    logger.info(
        "db.init_pool",
        host=settings.db_host,
        port=settings.db_port,
        database=settings.db_name,
        pool_min=settings.db_pool_min,
        pool_max=settings.db_pool_max,
    )

    _pool = await asyncpg.create_pool(
        dsn=settings.async_dsn,
        min_size=settings.db_pool_min,
        max_size=settings.db_pool_max,
        command_timeout=30,
        server_settings={
            "application_name": "w46",
            "timezone": "UTC",
        },
    )
    return _pool


async def close_pool() -> None:
    """Close the pool. Call on shutdown."""
    global _pool
    if _pool:
        await _pool.close()
        _pool = None
        logger.info("db.pool_closed")


def get_pool() -> asyncpg.Pool:
    """Get the current pool. Raises if not initialized."""
    if _pool is None:
        raise RuntimeError("Database pool not initialized. Call init_pool() first.")
    return _pool


# ── Advisory Lock Helpers ──────────────────────────────────

def _wallet_lock_id(wallet_id: str) -> int:
    """
    Derive a stable int64 advisory lock ID from a wallet UUID.
    PostgreSQL advisory locks need a bigint key.
    """
    h = hashlib.sha256(wallet_id.encode()).digest()
    return struct.unpack(">q", h[:8])[0]


@asynccontextmanager
async def wallet_lock(conn: asyncpg.Connection, wallet_id: str) -> AsyncGenerator[None, None]:
    """
    Acquire a PostgreSQL advisory lock scoped to a wallet.
    Prevents concurrent balance modifications / transaction processing.
    Released automatically when the context exits (even on error).
    """
    lock_id = _wallet_lock_id(wallet_id)
    try:
        await conn.execute("SELECT pg_advisory_lock($1)", lock_id)
        logger.debug("db.advisory_lock_acquired", wallet_id=wallet_id, lock_id=lock_id)
        yield
    finally:
        await conn.execute("SELECT pg_advisory_unlock($1)", lock_id)
        logger.debug("db.advisory_lock_released", wallet_id=wallet_id, lock_id=lock_id)


# ── Convenience Query Helpers ──────────────────────────────

async def fetchrow(query: str, *args: Any) -> Optional[asyncpg.Record]:
    """Execute a query and return a single row."""
    pool = get_pool()
    async with pool.acquire() as conn:
        return await conn.fetchrow(query, *args)


async def fetch(query: str, *args: Any) -> List[asyncpg.Record]:
    """Execute a query and return all rows."""
    pool = get_pool()
    async with pool.acquire() as conn:
        return await conn.fetch(query, *args)


async def execute(query: str, *args: Any) -> str:
    """Execute a query (INSERT/UPDATE/DELETE) and return the status string."""
    pool = get_pool()
    async with pool.acquire() as conn:
        return await conn.execute(query, *args)


async def fetchval(query: str, *args: Any) -> Any:
    """Execute a query and return a single value."""
    pool = get_pool()
    async with pool.acquire() as conn:
        return await conn.fetchval(query, *args)


@asynccontextmanager
async def transaction() -> AsyncGenerator[asyncpg.Connection, None]:
    """Context manager for a database transaction."""
    pool = get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            yield conn


async def health_check() -> Dict[str, Any]:
    """Check database connectivity and return stats."""
    pool = get_pool()
    try:
        version = await pool.fetchval("SELECT version()")
        size = pool.get_size()
        free = pool.get_idle_size()
        return {
            "status": "healthy",
            "version": version,
            "pool_size": size,
            "pool_idle": free,
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
        }
