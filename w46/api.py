"""
W46 API — FastAPI router with all endpoints.

Route groups:
- /auth      — signup, verify email, ToS, API keys
- /wallets   — CRUD, freeze, close
- /payments  — pay, approve, list transactions
- /policies  — get, update
- /proof     — verify chain, anchors
- /reputation — trust score, AFID
- /admin     — reconciliation, fees, audit (operator-only)
- /health    — system health
"""

from __future__ import annotations

import json
from decimal import Decimal
from typing import Any, Dict, List, Optional
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from w46 import services
from w46.auth import (
    accept_tos,
    create_api_key,
    rotate_api_key,
    signup,
    submit_kyb,
    verify_email,
)
from w46.exceptions import W46Error
from w46.middleware import require_auth
from w46.models import (
    APIKeyCreateRequest,
    APIKeyCreatedResponse,
    EmailVerifyRequest,
    HealthResponse,
    KYBSubmitRequest,
    OrgCreateRequest,
    PaymentRequest,
    PolicyCreateRequest,
    TOSAcceptRequest,
    WalletCreateRequest,
)

logger = structlog.get_logger(__name__)

# ============================================================
# Router Factory
# ============================================================

def create_router() -> APIRouter:
    router = APIRouter()

    # ── Auth Routes ────────────────────────────────────────

    auth_router = APIRouter(prefix="/auth", tags=["Authentication"])

    @auth_router.post("/signup")
    async def route_signup(req: OrgCreateRequest, request: Request):
        ip = request.client.host if request.client else None
        result = await signup(req.name, req.email, req.password, ip_address=ip)
        return JSONResponse(status_code=201, content=result)

    @auth_router.post("/verify-email")
    async def route_verify_email(req: EmailVerifyRequest):
        return await verify_email(req.token)

    @auth_router.post("/accept-tos")
    async def route_accept_tos(
        req: TOSAcceptRequest,
        request: Request,
        auth: dict = Depends(require_auth),
    ):
        ip = request.client.host if request.client else None
        return await accept_tos(auth["org_id"], req.version, ip_address=ip)

    @auth_router.post("/kyb")
    async def route_submit_kyb(
        req: KYBSubmitRequest,
        request: Request,
        auth: dict = Depends(require_auth),
    ):
        ip = request.client.host if request.client else None
        return await submit_kyb(auth["org_id"], req.model_dump(), ip_address=ip)

    @auth_router.post("/api-keys")
    async def route_create_api_key(
        req: APIKeyCreateRequest,
        request: Request,
        auth: dict = Depends(require_auth),
    ):
        ip = request.client.host if request.client else None
        result = await create_api_key(
            auth["org_id"],
            mode=req.mode.value,
            label=req.label,
            ip_address=ip,
        )
        return JSONResponse(status_code=201, content=result)

    @auth_router.post("/api-keys/{key_id}/rotate")
    async def route_rotate_api_key(
        key_id: UUID,
        request: Request,
        auth: dict = Depends(require_auth),
    ):
        ip = request.client.host if request.client else None
        return await rotate_api_key(auth["org_id"], key_id, ip_address=ip)

    router.include_router(auth_router)

    # ── Wallet Routes ──────────────────────────────────────

    wallet_router = APIRouter(prefix="/wallets", tags=["Wallets"])

    @wallet_router.post("")
    async def route_create_wallet(
        req: WalletCreateRequest,
        request: Request,
        auth: dict = Depends(require_auth),
    ):
        ip = request.client.host if request.client else None
        result = await services.create_wallet(
            org_id=auth["org_id"],
            agent_id=req.agent_id,
            label=req.label,
            metadata=req.metadata,
            actor=f"api_key:{auth.get('key_prefix', 'unknown')}",
            ip_address=ip,
        )
        # Convert non-serializable types
        return JSONResponse(status_code=201, content=_serialize(result))

    @wallet_router.get("")
    async def route_list_wallets(
        auth: dict = Depends(require_auth),
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
    ):
        wallets = await services.list_wallets(auth["org_id"], limit=limit, offset=offset)
        return [_serialize(w) for w in wallets]

    @wallet_router.get("/{wallet_id}")
    async def route_get_wallet(
        wallet_id: UUID,
        auth: dict = Depends(require_auth),
    ):
        wallet = await services.get_wallet(auth["org_id"], wallet_id)
        return _serialize(wallet)

    @wallet_router.post("/{wallet_id}/freeze")
    async def route_freeze_wallet(
        wallet_id: UUID,
        request: Request,
        auth: dict = Depends(require_auth),
    ):
        ip = request.client.host if request.client else None
        return await services.freeze_wallet(
            auth["org_id"], wallet_id,
            actor=f"api_key:{auth.get('key_prefix', '')}",
            ip_address=ip,
        )

    @wallet_router.post("/{wallet_id}/close")
    async def route_close_wallet(
        wallet_id: UUID,
        request: Request,
        auth: dict = Depends(require_auth),
    ):
        ip = request.client.host if request.client else None
        return await services.close_wallet(
            auth["org_id"], wallet_id,
            actor=f"api_key:{auth.get('key_prefix', '')}",
            ip_address=ip,
        )

    router.include_router(wallet_router)

    # ── Payment Routes ─────────────────────────────────────

    payment_router = APIRouter(prefix="/wallets/{wallet_id}/payments", tags=["Payments"])

    @payment_router.post("")
    async def route_pay(
        wallet_id: UUID,
        req: PaymentRequest,
        request: Request,
        auth: dict = Depends(require_auth),
    ):
        ip = request.client.host if request.client else None
        from w46.settlement import process_payment

        result = await process_payment(
            org_id=auth["org_id"],
            wallet_id=wallet_id,
            to_address=req.to_address,
            amount_usdc=req.amount_usdc,
            memo=req.memo,
            category=req.category,
            idempotency_key=req.idempotency_key,
            metadata=req.metadata,
            preferred_rail=req.preferred_rail,
            actor=f"api_key:{auth.get('key_prefix', '')}",
            ip_address=ip,
        )
        return JSONResponse(status_code=201, content=_serialize(result))

    @payment_router.get("")
    async def route_list_payments(
        wallet_id: UUID,
        auth: dict = Depends(require_auth),
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
    ):
        txs = await services.list_transactions(
            auth["org_id"], wallet_id=wallet_id, limit=limit, offset=offset
        )
        return [_serialize(t) for t in txs]

    router.include_router(payment_router)

    # ── Transaction Routes ─────────────────────────────────

    tx_router = APIRouter(prefix="/transactions", tags=["Transactions"])

    @tx_router.get("")
    async def route_list_all_transactions(
        auth: dict = Depends(require_auth),
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
    ):
        txs = await services.list_transactions(auth["org_id"], limit=limit, offset=offset)
        return [_serialize(t) for t in txs]

    @tx_router.get("/{tx_id}")
    async def route_get_transaction(
        tx_id: UUID,
        auth: dict = Depends(require_auth),
    ):
        tx = await services.get_transaction(auth["org_id"], tx_id)
        return _serialize(tx)

    @tx_router.post("/{tx_id}/approve")
    async def route_approve_transaction(
        tx_id: UUID,
        request: Request,
        auth: dict = Depends(require_auth),
        approved: bool = Query(True),
    ):
        ip = request.client.host if request.client else None
        from w46.settlement import approve_human_review

        result = await approve_human_review(
            tx_id=tx_id,
            org_id=auth["org_id"],
            approved=approved,
            actor=f"api_key:{auth.get('key_prefix', '')}",
            ip_address=ip,
        )
        return _serialize(result)

    router.include_router(tx_router)

    # ── Policy Routes ──────────────────────────────────────

    policy_router = APIRouter(prefix="/wallets/{wallet_id}/policy", tags=["Policies"])

    @policy_router.get("")
    async def route_get_policy(
        wallet_id: UUID,
        auth: dict = Depends(require_auth),
    ):
        from w46 import db
        from w46.policy import load_policy_snapshot

        # Verify ownership
        await services.get_wallet(auth["org_id"], wallet_id)
        pool = db.get_pool()
        async with pool.acquire() as conn:
            snapshot = await load_policy_snapshot(conn, wallet_id)
        return snapshot.to_dict()

    @policy_router.put("")
    async def route_update_policy(
        wallet_id: UUID,
        req: PolicyCreateRequest,
        request: Request,
        auth: dict = Depends(require_auth),
    ):
        ip = request.client.host if request.client else None
        result = await services.update_policy(
            auth["org_id"],
            wallet_id,
            req.model_dump(mode="json"),
            actor=f"api_key:{auth.get('key_prefix', '')}",
            ip_address=ip,
        )
        return _serialize(result)

    router.include_router(policy_router)

    # ── Proof Routes ───────────────────────────────────────

    proof_router = APIRouter(prefix="/proof", tags=["Proof & Integrity"])

    @proof_router.get("/wallets/{wallet_id}/verify")
    async def route_verify_proof_chain(
        wallet_id: UUID,
        auth: dict = Depends(require_auth),
    ):
        await services.get_wallet(auth["org_id"], wallet_id)
        from w46.proof import verify_wallet_chain
        return await verify_wallet_chain(wallet_id)

    @proof_router.get("/audit/verify")
    async def route_verify_audit_chain(
        auth: dict = Depends(require_auth),
    ):
        from w46.audit import verify_chain
        return await verify_chain(org_id=auth["org_id"])

    @proof_router.get("/anchors")
    async def route_list_anchors(
        auth: dict = Depends(require_auth),
        limit: int = Query(20, ge=1, le=100),
    ):
        from w46 import db
        rows = await db.fetch(
            "SELECT * FROM anchor_batches ORDER BY created_at DESC LIMIT $1",
            limit,
        )
        return [_serialize(dict(r)) for r in rows]

    router.include_router(proof_router)

    # ── Reputation & AFID Routes ───────────────────────────

    rep_router = APIRouter(prefix="/wallets/{wallet_id}", tags=["Reputation & AFID"])

    @rep_router.get("/reputation")
    async def route_get_reputation(
        wallet_id: UUID,
        auth: dict = Depends(require_auth),
    ):
        await services.get_wallet(auth["org_id"], wallet_id)
        from w46.reputation import calculate_trust_score
        from w46 import db

        pool = db.get_pool()
        async with pool.acquire() as conn:
            return await calculate_trust_score(conn, wallet_id)

    @rep_router.get("/afid")
    async def route_get_afid(
        wallet_id: UUID,
        auth: dict = Depends(require_auth),
    ):
        await services.get_wallet(auth["org_id"], wallet_id)
        from w46.afid import generate_afid
        from w46 import db

        pool = db.get_pool()
        async with pool.acquire() as conn:
            return await generate_afid(conn, wallet_id)

    @rep_router.post("/afid/verify")
    async def route_verify_afid(
        wallet_id: UUID,
        afid_document: Dict[str, Any],
        auth: dict = Depends(require_auth),
    ):
        from w46.afid import verify_afid
        return await verify_afid(afid_document)

    router.include_router(rep_router)

    # ── Admin Routes ───────────────────────────────────────

    admin_router = APIRouter(prefix="/admin", tags=["Admin"])

    @admin_router.post("/reconcile")
    async def route_reconcile_all(auth: dict = Depends(require_auth)):
        from w46.reconciliation import reconcile_all_wallets
        return await reconcile_all_wallets()

    @admin_router.post("/reconcile/{wallet_id}")
    async def route_reconcile_wallet(
        wallet_id: UUID,
        auth: dict = Depends(require_auth),
    ):
        from w46.reconciliation import reconcile_wallet
        return await reconcile_wallet(wallet_id)

    @admin_router.get("/fees")
    async def route_get_fees(auth: dict = Depends(require_auth)):
        from w46.fees import get_pending_fees
        return await get_pending_fees()

    @admin_router.post("/fees/sweep")
    async def route_sweep_fees(auth: dict = Depends(require_auth)):
        from w46.fees import sweep_fees
        return await sweep_fees()

    @admin_router.get("/circuit-breakers")
    async def route_circuit_breakers(auth: dict = Depends(require_auth)):
        from w46.routing import get_breaker_states
        return get_breaker_states()

    router.include_router(admin_router)

    return router


# ============================================================
# Serialization Helper
# ============================================================

def _serialize(obj: Any) -> Any:
    """Make any dict JSON-serializable (handle UUID, Decimal, datetime, etc)."""
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_serialize(v) for v in obj]
    elif isinstance(obj, UUID):
        return str(obj)
    elif isinstance(obj, Decimal):
        return str(obj)
    elif hasattr(obj, "isoformat"):
        return obj.isoformat()
    elif isinstance(obj, bytes):
        return obj.hex()
    return obj
