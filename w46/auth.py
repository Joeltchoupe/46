"""
W46 Auth — API key management, hashing, verification, and org authentication.

Flow:
1. Org signs up (email + password)
2. Email verification token sent
3. Org verifies email
4. Org accepts ToS
5. Org creates API key (sandbox or live)
6. Live mode requires KYB approval
7. API key used in Authorization header for all API calls

API keys are hashed with PBKDF2-SHA256. Only the hash is stored.
The raw key is shown once at creation and never again.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional, Tuple
from uuid import UUID

import asyncpg
import structlog

from w46 import db, audit
from w46.config import get_settings
from w46.exceptions import (
    AuthenticationError,
    AuthorizationError,
    DuplicateEmailError,
    EmailNotVerifiedError,
    KYBRequiredError,
    OrgNotFoundError,
)

logger = structlog.get_logger(__name__)


# ============================================================
# Password Hashing
# ============================================================

def hash_password(password: str) -> str:
    """Hash a password with PBKDF2-SHA256 + random salt."""
    salt = os.urandom(32)
    iterations = get_settings().api_key_hash_iterations
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2:sha256:{iterations}${salt.hex()}${dk.hex()}"


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its hash."""
    try:
        parts = password_hash.split("$")
        header = parts[0]  # pbkdf2:sha256:100000
        salt_hex = parts[1]
        stored_dk = parts[2]

        iterations = int(header.split(":")[-1])
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)

        return hmac.compare_digest(dk.hex(), stored_dk)
    except (IndexError, ValueError):
        return False


# ============================================================
# API Key Generation & Hashing
# ============================================================

def generate_api_key(mode: str = "sandbox") -> Tuple[str, str, str]:
    """
    Generate a new API key.
    
    Returns: (full_key, key_hash, key_prefix)
    """
    prefix = f"w46_{mode}_"
    random_part = secrets.token_urlsafe(32)
    full_key = f"{prefix}{random_part}"
    key_hash = _hash_api_key(full_key)
    key_prefix = full_key[:16]
    return full_key, key_hash, key_prefix


def _hash_api_key(api_key: str) -> str:
    """Hash an API key with SHA-256 (fast lookup, key is already high-entropy)."""
    return hashlib.sha256(api_key.encode()).hexdigest()


async def verify_api_key(api_key: str) -> Optional[Dict[str, Any]]:
    """
    Verify an API key and return the org + key metadata.
    
    Returns None if invalid.
    """
    key_hash = _hash_api_key(api_key)

    pool = db.get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT ak.id as key_id, ak.org_id, ak.mode, ak.label,
                   o.name as org_name, o.email, o.email_verified,
                   o.mode as org_mode, o.kyb_status
            FROM api_keys ak
            JOIN organizations o ON o.id = ak.org_id
            WHERE ak.key_hash = $1
              AND ak.is_active = TRUE
              AND (ak.expires_at IS NULL OR ak.expires_at > NOW())
            """,
            key_hash,
        )

        if not row:
            return None

        # Update last_used_at
        await conn.execute(
            "UPDATE api_keys SET last_used_at = NOW() WHERE key_hash = $1",
            key_hash,
        )

        return dict(row)


# ============================================================
# Signup Flow
# ============================================================

async def signup(
    name: str,
    email: str,
    password: str,
    ip_address: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create a new organization.
    
    Returns org data + email verification token.
    """
    settings = get_settings()
    pool = db.get_pool()

    async with pool.acquire() as conn:
        # Check duplicate
        existing = await conn.fetchval(
            "SELECT id FROM organizations WHERE email = $1",
            email.lower(),
        )
        if existing:
            raise DuplicateEmailError()

        pwd_hash = hash_password(password)
        email_token = secrets.token_urlsafe(48)
        token_exp = datetime.now(timezone.utc) + timedelta(seconds=settings.verification_token_ttl_sec)

        org_id = await conn.fetchval(
            """
            INSERT INTO organizations (name, email, password_hash, email_token, email_token_exp)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
            """,
            name,
            email.lower(),
            pwd_hash,
            email_token,
            token_exp,
        )

        await audit.log(
            "org_created",
            "system",
            org_id=org_id,
            details={"name": name, "email": email.lower()},
            ip_address=ip_address,
            conn=conn,
        )

        logger.info("auth.org_created", org_id=str(org_id), email=email.lower())

        return {
            "org_id": str(org_id),
            "email": email.lower(),
            "email_token": email_token,
            "message": "Verify your email to continue",
        }


async def verify_email(token: str) -> Dict[str, Any]:
    """Verify an email with the token sent during signup."""
    pool = db.get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT id, email FROM organizations
            WHERE email_token = $1
              AND email_token_exp > NOW()
              AND email_verified = FALSE
            """,
            token,
        )

        if not row:
            raise AuthenticationError("Invalid or expired verification token")

        await conn.execute(
            """
            UPDATE organizations
            SET email_verified = TRUE, email_token = NULL, email_token_exp = NULL
            WHERE id = $1
            """,
            row["id"],
        )

        await audit.log(
            "org_updated",
            "system",
            org_id=row["id"],
            details={"action": "email_verified"},
            conn=conn,
        )

        return {"org_id": str(row["id"]), "email": row["email"], "verified": True}


async def accept_tos(
    org_id: UUID,
    version: str,
    ip_address: Optional[str] = None,
) -> Dict[str, Any]:
    """Record ToS acceptance."""
    pool = db.get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE organizations
            SET tos_accepted_at = NOW(), tos_ip = $1::inet, tos_version = $2
            WHERE id = $3
            """,
            ip_address,
            version,
            org_id,
        )

        await audit.log(
            "org_updated",
            f"org:{org_id}",
            org_id=org_id,
            details={"action": "tos_accepted", "version": version},
            ip_address=ip_address,
            conn=conn,
        )

        return {"accepted": True, "version": version}


async def submit_kyb(
    org_id: UUID,
    kyb_data: Dict[str, Any],
    ip_address: Optional[str] = None,
) -> Dict[str, Any]:
    """Submit KYB data for review."""
    pool = db.get_pool()
    async with pool.acquire() as conn:
        org = await conn.fetchrow(
            "SELECT email_verified FROM organizations WHERE id = $1",
            org_id,
        )
        if not org:
            raise OrgNotFoundError()
        if not org["email_verified"]:
            raise EmailNotVerifiedError()

        await conn.execute(
            """
            UPDATE organizations
            SET kyb_status = 'pending', kyb_data = $1::jsonb
            WHERE id = $2
            """,
            json.dumps(kyb_data) if not isinstance(kyb_data, str) else kyb_data,
            org_id,
        )

        await audit.log(
            "kyb_submitted",
            f"org:{org_id}",
            org_id=org_id,
            details={"company": kyb_data.get("company_name", "")},
            ip_address=ip_address,
            conn=conn,
        )

        return {"kyb_status": "pending"}


import json


async def create_api_key(
    org_id: UUID,
    mode: str = "sandbox",
    label: str = "default",
    ip_address: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create a new API key for an organization.
    
    Live mode requires KYB approval.
    Returns the full key (shown only once).
    """
    pool = db.get_pool()
    async with pool.acquire() as conn:
        org = await conn.fetchrow(
            "SELECT email_verified, kyb_status FROM organizations WHERE id = $1",
            org_id,
        )
        if not org:
            raise OrgNotFoundError()
        if not org["email_verified"]:
            raise EmailNotVerifiedError()
        if mode == "live" and org["kyb_status"] != "approved":
            raise KYBRequiredError()

        full_key, key_hash, key_prefix = generate_api_key(mode)

        key_id = await conn.fetchval(
            """
            INSERT INTO api_keys (org_id, key_hash, key_prefix, label, mode)
            VALUES ($1, $2, $3, $4, $5::env_mode)
            RETURNING id
            """,
            org_id,
            key_hash,
            key_prefix,
            label,
            mode,
        )

        await audit.log(
            "api_key_created",
            f"org:{org_id}",
            org_id=org_id,
            details={"key_prefix": key_prefix, "mode": mode, "label": label},
            ip_address=ip_address,
            conn=conn,
        )

        return {
            "key_id": str(key_id),
            "api_key": full_key,
            "key_prefix": key_prefix,
            "mode": mode,
            "label": label,
            "message": "Store this key securely. It will not be shown again.",
        }


async def rotate_api_key(
    org_id: UUID,
    old_key_id: UUID,
    ip_address: Optional[str] = None,
) -> Dict[str, Any]:
    """Revoke old key and create new one with the same config."""
    pool = db.get_pool()
    async with pool.acquire() as conn:
        old_key = await conn.fetchrow(
            "SELECT mode, label FROM api_keys WHERE id = $1 AND org_id = $2 AND is_active = TRUE",
            old_key_id,
            org_id,
        )
        if not old_key:
            raise AuthenticationError("API key not found or already revoked")

        # Revoke old
        await conn.execute(
            "UPDATE api_keys SET is_active = FALSE, revoked_at = NOW() WHERE id = $1",
            old_key_id,
        )

        await audit.log(
            "api_key_revoked",
            f"org:{org_id}",
            org_id=org_id,
            details={"key_id": str(old_key_id)},
            ip_address=ip_address,
            conn=conn,
        )

    # Create new
    return await create_api_key(
        org_id=org_id,
        mode=old_key["mode"],
        label=old_key["label"],
        ip_address=ip_address,
    )
