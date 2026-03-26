# ============================================================
# W46 — Production-Ready Lite Container
# Multi-stage build for minimal attack surface
# ============================================================

# ── Stage 1: Builder ───────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: Runtime ──────────────────────────────────────
FROM python:3.12-slim AS runtime

LABEL maintainer="W46 <infra@w46.io>"
LABEL description="W46 — USDC Wallet Infrastructure for AI Agents"

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r w46 && useradd -r -g w46 -d /app -s /sbin/nologin w46

COPY --from=builder /install /usr/local

WORKDIR /app

COPY w46/ ./w46/
COPY w46_sdk.py .

RUN mkdir -p /app/data/keys && chown -R w46:w46 /app

USER w46

EXPOSE 8046

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8046/health || exit 1

CMD ["python", "-m", "uvicorn", "w46.main:app", "--host", "0.0.0.0", "--port", "8046", "--workers", "4", "--loop", "uvloop"]
