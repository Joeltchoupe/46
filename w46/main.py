"""
W46 Main — FastAPI application factory and lifecycle management.

Startup:
1. Validate production guards
2. Initialize database pool
3. Initialize Redis
4. Configure structured logging
5. Start background task scheduler
6. Mount API routes

Shutdown:
1. Stop scheduler
2. Close database pool
3. Close Redis
"""

from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from w46 import __version__
from w46.api import create_router
from w46.config import get_settings
from w46.db import close_pool, health_check as db_health, init_pool
from w46.exceptions import W46Error
from w46.middleware import (
    RateLimitMiddleware,
    RequestIDMiddleware,
    RequestLoggingMiddleware,
    close_redis,
    redis_health,
)
from w46.tasks import setup_scheduler


def configure_logging() -> None:
    """Configure structlog for structured JSON logging."""
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(
                __import__("logging"),
                get_settings().log_level.upper(),
                20,  # INFO
            )
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan: startup and shutdown."""
    logger = structlog.get_logger("w46.main")
    settings = get_settings()

    # ── Startup ────────────────────────────────────────────
    logger.info(
        "startup.begin",
        version=__version__,
        environment=settings.env.value,
        kms_provider=settings.kms_provider.value,
    )

    # Validate production guards
    try:
        settings.validate_production_guards()
    except ValueError as e:
        logger.error("startup.production_guard_failed", error=str(e))
        if settings.is_production:
            sys.exit(1)

    # Init database
    await init_pool()
    logger.info("startup.database_ready")

    # Start scheduler
    scheduler = setup_scheduler()
    scheduler.start()
    logger.info("startup.scheduler_started")

    logger.info("startup.complete", port=settings.api_port)

    yield

    # ── Shutdown ───────────────────────────────────────────
    logger.info("shutdown.begin")

    scheduler.shutdown(wait=False)
    logger.info("shutdown.scheduler_stopped")

    await close_pool()
    logger.info("shutdown.database_closed")

    await close_redis()
    logger.info("shutdown.redis_closed")

    logger.info("shutdown.complete")


def create_app() -> FastAPI:
    """Application factory."""
    configure_logging()
    settings = get_settings()

    app = FastAPI(
        title="W46",
        description="USDC Wallet Infrastructure for AI Agents",
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # ── Middleware (order: last added = first executed) ─────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(RequestIDMiddleware)

    # ── Exception Handlers ─────────────────────────────────

    @app.exception_handler(W46Error)
    async def w46_error_handler(request: Request, exc: W46Error) -> JSONResponse:
        return JSONResponse(
            status_code=exc.http_status,
            content=exc.to_dict(),
        )

    @app.exception_handler(Exception)
    async def generic_error_handler(request: Request, exc: Exception) -> JSONResponse:
        logger = structlog.get_logger("w46.error")
        logger.error(
            "unhandled_exception",
            error=str(exc),
            type=type(exc).__name__,
            path=request.url.path,
        )
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "An internal error occurred",
                }
            },
        )

    # ── Health Endpoint ────────────────────────────────────

    @app.get("/health", tags=["Health"])
    async def health():
        from w46.blockchain.factory import health_check_all

        db_status = await db_health()
        redis_status = await redis_health()

        try:
            blockchain_status = await health_check_all()
        except Exception as e:
            blockchain_status = {"error": str(e)}

        overall = "healthy"
        if db_status.get("status") != "healthy":
            overall = "degraded"
        if redis_status.get("status") != "healthy":
            overall = "degraded"

        return {
            "status": overall,
            "version": __version__,
            "environment": settings.env.value,
            "database": db_status,
            "redis": redis_status,
            "blockchain": blockchain_status,
        }

    # ── API Routes ─────────────────────────────────────────
    router = create_router()
    app.include_router(router, prefix="/v1")

    return app


# ── ASGI Entry Point ──────────────────────────────────────
app = create_app()
