"""
W46 Exceptions — Typed error hierarchy for clean error handling.

Every exception carries a machine-readable code, a human message,
and an optional HTTP status code for the API layer.
"""

from __future__ import annotations

from typing import Any, Dict, Optional


class W46Error(Exception):
    """Base exception for all W46 errors."""

    code: str = "W46_INTERNAL_ERROR"
    http_status: int = 500

    def __init__(
        self,
        message: str = "An internal error occurred",
        *,
        details: Optional[Dict[str, Any]] = None,
    ):
        self.message = message
        self.details = details or {}
        super().__init__(self.message)

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "error": {
                "code": self.code,
                "message": self.message,
            }
        }
        if self.details:
            payload["error"]["details"] = self.details
        return payload


# ── Auth Errors ────────────────────────────────────────────

class AuthenticationError(W46Error):
    code = "AUTH_FAILED"
    http_status = 401

    def __init__(self, message: str = "Authentication failed", **kwargs):
        super().__init__(message, **kwargs)


class AuthorizationError(W46Error):
    code = "FORBIDDEN"
    http_status = 403

    def __init__(self, message: str = "Insufficient permissions", **kwargs):
        super().__init__(message, **kwargs)


class RateLimitError(W46Error):
    code = "RATE_LIMITED"
    http_status = 429

    def __init__(self, message: str = "Rate limit exceeded", **kwargs):
        super().__init__(message, **kwargs)


# ── Org / KYB Errors ──────────────────────────────────────

class OrgNotFoundError(W46Error):
    code = "ORG_NOT_FOUND"
    http_status = 404

    def __init__(self, message: str = "Organization not found", **kwargs):
        super().__init__(message, **kwargs)


class EmailNotVerifiedError(W46Error):
    code = "EMAIL_NOT_VERIFIED"
    http_status = 403

    def __init__(self, message: str = "Email not verified", **kwargs):
        super().__init__(message, **kwargs)


class KYBRequiredError(W46Error):
    code = "KYB_REQUIRED"
    http_status = 403

    def __init__(self, message: str = "KYB approval required for live mode", **kwargs):
        super().__init__(message, **kwargs)


class DuplicateEmailError(W46Error):
    code = "DUPLICATE_EMAIL"
    http_status = 409

    def __init__(self, message: str = "Email already registered", **kwargs):
        super().__init__(message, **kwargs)


# ── Wallet Errors ──────────────────────────────────────────

class WalletNotFoundError(W46Error):
    code = "WALLET_NOT_FOUND"
    http_status = 404

    def __init__(self, message: str = "Wallet not found", **kwargs):
        super().__init__(message, **kwargs)


class WalletFrozenError(W46Error):
    code = "WALLET_FROZEN"
    http_status = 403

    def __init__(self, message: str = "Wallet is frozen", **kwargs):
        super().__init__(message, **kwargs)


class WalletClosedError(W46Error):
    code = "WALLET_CLOSED"
    http_status = 403

    def __init__(self, message: str = "Wallet is closed", **kwargs):
        super().__init__(message, **kwargs)


class DuplicateWalletError(W46Error):
    code = "DUPLICATE_WALLET"
    http_status = 409

    def __init__(self, message: str = "Wallet with this agent_id already exists", **kwargs):
        super().__init__(message, **kwargs)


class KMSNotConfiguredError(W46Error):
    code = "KMS_NOT_CONFIGURED"
    http_status = 503

    def __init__(self, message: str = "KMS not configured — cannot create wallets in production", **kwargs):
        super().__init__(message, **kwargs)


# ── Policy Errors ──────────────────────────────────────────

class PolicyViolationError(W46Error):
    code = "POLICY_VIOLATION"
    http_status = 403

    def __init__(self, message: str = "Transaction violates policy", **kwargs):
        super().__init__(message, **kwargs)


class HumanApprovalRequiredError(W46Error):
    code = "HUMAN_APPROVAL_REQUIRED"
    http_status = 202

    def __init__(self, message: str = "Human approval required for this amount", **kwargs):
        super().__init__(message, **kwargs)


# ── Transaction Errors ─────────────────────────────────────

class TransactionNotFoundError(W46Error):
    code = "TX_NOT_FOUND"
    http_status = 404

    def __init__(self, message: str = "Transaction not found", **kwargs):
        super().__init__(message, **kwargs)


class InsufficientBalanceError(W46Error):
    code = "INSUFFICIENT_BALANCE"
    http_status = 400

    def __init__(self, message: str = "Insufficient USDC balance", **kwargs):
        super().__init__(message, **kwargs)


class SettlementError(W46Error):
    code = "SETTLEMENT_FAILED"
    http_status = 502

    def __init__(self, message: str = "Blockchain settlement failed", **kwargs):
        super().__init__(message, **kwargs)


class AllRailsDownError(W46Error):
    code = "ALL_RAILS_DOWN"
    http_status = 503

    def __init__(self, message: str = "All blockchain rails are unavailable", **kwargs):
        super().__init__(message, **kwargs)


class IdempotencyConflictError(W46Error):
    code = "IDEMPOTENCY_CONFLICT"
    http_status = 409

    def __init__(self, message: str = "Transaction with this idempotency key already exists", **kwargs):
        super().__init__(message, **kwargs)


# ── Proof / Integrity Errors ──────────────────────────────

class ProofChainBrokenError(W46Error):
    code = "PROOF_CHAIN_BROKEN"
    http_status = 500

    def __init__(self, message: str = "Proof hash chain integrity violation detected", **kwargs):
        super().__init__(message, **kwargs)


class ReconciliationMismatchError(W46Error):
    code = "RECONCILIATION_MISMATCH"
    http_status = 500

    def __init__(self, message: str = "Ledger/blockchain balance mismatch detected", **kwargs):
        super().__init__(message, **kwargs)
