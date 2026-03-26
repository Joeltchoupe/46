"""
W46 Middleware — Rate limiting, API key auth extraction, request logging.

Middleware stack (order matters):
1. Request ID injection
2. Structured request logging
3. Rate limiting (per API key, via Redis)
4. API key extraction and org context injection
"""

from __future__ import annotations

import time
import uuid
from typing import Optional

import redis.asyncio as aioredis
import structlog
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from w46.auth import verify_api_key
from w46.config import get_settings
from w46.exceptions import AuthenticationError, RateLimitError

logger = structlog.get_logger(__name__)

# ── Redis client (lazy init) ──────────────────────────────
_redis: Optional[aioredis.Redis] = None


async def get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        settings = get_settings()
        _redis = aioredis.from_url(
            settings.redis_url,
            decode_responses=True,
            max_connections=20,
        )
    return _redis


async def close_redis() -> None:
    global _redis
    if _redis:
        await _redis.close()
        _redis = None


async def redis_health() -> dict:
    try:
        r = await get_redis()
        await r.ping()
        return {"status": "healthy"}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}


# ============================================================
# Request ID Middleware
# ============================================================

class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        request.state.request_id = request_id

        structlog.contextvars.bind_contextvars(request_id=request_id)

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id

        structlog.contextvars.unbind_contextvars("request_id")
        return response


# ============================================================
# Request Logging Middleware
# ============================================================

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        start = time.time()

        response = await call_next(request)

        elapsed_ms = (time.time() - start) * 1000
        logger.info(
            "http.request",
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            elapsed_ms=round(elapsed_ms, 2),
            client=request.client.host if request.client else None,
        )

        return response


# ============================================================
# Rate Limiting Middleware
# ============================================================

class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Token bucket rate limiting per API key via Redis.
    
    Limits: W46_RATE_LIMIT_PER_MINUTE requests per minute per API key.
    Public endpoints (health, docs) are exempt.
    """

    EXEMPT_PATHS = {"/health", "/docs", "/openapi.json", "/redoc"}

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        # Extract API key for rate limit key
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            # No API key — will be caught by auth middleware
            return await call_next(request)

        api_key = auth_header[7:]
        settings = get_settings()

        try:
            r = await get_redis()
            rate_key = f"w46:rate:{api_key[:16]}"

            # Sliding window counter
            current = await r.get(rate_key)
            if current and int(current) >= settings.rate_limit_per_minute:
                logger.warning("rate_limit.exceeded", key_prefix=api_key[:16])
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": {
                            "code": "RATE_LIMITED",
                            "message": f"Rate limit exceeded: {settings.rate_limit_per_minute}/min",
                        }
                    },
                    headers={"Retry-After": "60"},
                )

            pipe = r.pipeline()
            pipe.incr(rate_key)
            pipe.expire(rate_key, 60)
            await pipe.execute()

        except Exception as e:
            # If Redis is down, allow the request (fail open for rate limiting)
            logger.warning("rate_limit.redis_error", error=str(e))

        return await call_next(request)


# ============================================================
# Auth Dependency (not middleware — used as FastAPI Depends)
# ============================================================

async def require_auth(request: Request) -> dict:
    """
    FastAPI dependency that extracts and verifies the API key.
    
    Injects org context into the request.
    Raises AuthenticationError if key is invalid.
    """
    auth_header = request.headers.get("Authorization", "")

    if not auth_header.startswith("Bearer "):
        raise AuthenticationError("Missing or invalid Authorization header. Use: Bearer <api_key>")

    api_key = auth_header[7:].strip()
    if not api_key:
        raise AuthenticationError("Empty API key")

    auth_ctx = await verify_api_key(api_key)
    if not auth_ctx:
        raise AuthenticationError("Invalid API key")

    # Inject into request state for downstream use
    request.state.org_id = auth_ctx["org_id"]
    request.state.org_name = auth_ctx["org_name"]
    request.state.key_mode = auth_ctx["mode"]
    request.state.key_prefix = api_key[:16]
    request.state.email_verified = auth_ctx["email_verified"]
    request.state.kyb_status = auth_ctx["kyb_status"]

    structlog.contextvars.bind_contextvars(
        org_id=str(auth_ctx["org_id"]),
        key_prefix=api_key[:16],
    )

    return auth_ctx
