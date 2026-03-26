"""
W46 Python SDK — Developer-friendly client for the W46 API.

Usage:
    from w46_sdk import W46Client

    w = W46Client(api_key="w46_sandbox_abc...")
    
    # Create wallet for your agent
    wallet = w.wallets.create(agent_id="my-trading-agent")
    
    # Pay for a service
    tx = w.wallets.pay(
        wallet_id=wallet["id"],
        to_address="recipient_solana_or_base_address",
        amount_usdc=5.00,
        memo="API call to data provider",
    )
    
    # Check proof integrity
    proof = w.proof.verify_chain(wallet_id=wallet["id"])
"""

from __future__ import annotations

import time
from decimal import Decimal
from typing import Any, Dict, List, Optional
from uuid import UUID

import httpx


class W46Error(Exception):
    """SDK error wrapping API error responses."""

    def __init__(self, status_code: int, error: Dict[str, Any]):
        self.status_code = status_code
        self.code = error.get("code", "UNKNOWN")
        self.message = error.get("message", "Unknown error")
        self.details = error.get("details", {})
        super().__init__(f"[{self.code}] {self.message}")


class _Resource:
    """Base class for API resource groups."""

    def __init__(self, client: W46Client):
        self._client = client

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Dict] = None,
        params: Optional[Dict] = None,
    ) -> Any:
        return self._client._request(method, path, json=json, params=params)


class _Wallets(_Resource):
    """Wallet operations."""

    def create(
        self,
        agent_id: str,
        *,
        label: Optional[str] = None,
        metadata: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """Create a new wallet for an AI agent."""
        payload: Dict[str, Any] = {"agent_id": agent_id}
        if label:
            payload["label"] = label
        if metadata:
            payload["metadata"] = metadata
        return self._request("POST", "/wallets", json=payload)

    def list(self, *, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """List all wallets."""
        return self._request("GET", "/wallets", params={"limit": limit, "offset": offset})

    def get(self, wallet_id: str) -> Dict[str, Any]:
        """Get wallet details."""
        return self._request("GET", f"/wallets/{wallet_id}")

    def freeze(self, wallet_id: str) -> Dict[str, Any]:
        """Freeze a wallet."""
        return self._request("POST", f"/wallets/{wallet_id}/freeze")

    def close(self, wallet_id: str) -> Dict[str, Any]:
        """Close a wallet permanently."""
        return self._request("POST", f"/wallets/{wallet_id}/close")

    def pay(
        self,
        wallet_id: str,
        to_address: str,
        amount_usdc: float | Decimal,
        *,
        memo: Optional[str] = None,
        category: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        metadata: Optional[Dict] = None,
        preferred_rail: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute a payment from a wallet.
        
        This is the main entry point for agent payments.
        """
        payload: Dict[str, Any] = {
            "to_address": to_address,
            "amount_usdc": str(amount_usdc),
        }
        if memo:
            payload["memo"] = memo
        if category:
            payload["category"] = category
        if idempotency_key:
            payload["idempotency_key"] = idempotency_key
        if metadata:
            payload["metadata"] = metadata
        if preferred_rail:
            payload["preferred_rail"] = preferred_rail

        return self._request("POST", f"/wallets/{wallet_id}/payments", json=payload)

    def list_payments(
        self,
        wallet_id: str,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """List payments for a wallet."""
        return self._request(
            "GET",
            f"/wallets/{wallet_id}/payments",
            params={"limit": limit, "offset": offset},
        )


class _Policies(_Resource):
    """Policy operations."""

    def get(self, wallet_id: str) -> Dict[str, Any]:
        """Get the active policy for a wallet."""
        return self._request("GET", f"/wallets/{wallet_id}/policy")

    def update(self, wallet_id: str, **policy_fields) -> Dict[str, Any]:
        """Update the policy for a wallet."""
        return self._request("PUT", f"/wallets/{wallet_id}/policy", json=policy_fields)


class _Transactions(_Resource):
    """Transaction operations."""

    def list(self, *, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """List all transactions."""
        return self._request("GET", "/transactions", params={"limit": limit, "offset": offset})

    def get(self, tx_id: str) -> Dict[str, Any]:
        """Get transaction details."""
        return self._request("GET", f"/transactions/{tx_id}")

    def approve(self, tx_id: str, approved: bool = True) -> Dict[str, Any]:
        """Approve or deny a human-approval-required transaction."""
        return self._request(
            "POST",
            f"/transactions/{tx_id}/approve",
            params={"approved": approved},
        )


class _Proof(_Resource):
    """Proof and integrity operations."""

    def verify_chain(self, wallet_id: str) -> Dict[str, Any]:
        """Verify the proof hash chain for a wallet."""
        return self._request("GET", f"/proof/wallets/{wallet_id}/verify")

    def verify_audit(self) -> Dict[str, Any]:
        """Verify the audit log hash chain."""
        return self._request("GET", "/proof/audit/verify")

    def list_anchors(self, *, limit: int = 20) -> List[Dict[str, Any]]:
        """List Merkle anchor batches."""
        return self._request("GET", "/proof/anchors", params={"limit": limit})


class _Reputation(_Resource):
    """Reputation and AFID operations."""

    def get_score(self, wallet_id: str) -> Dict[str, Any]:
        """Get the trust score for a wallet."""
        return self._request("GET", f"/wallets/{wallet_id}/reputation")

    def get_afid(self, wallet_id: str) -> Dict[str, Any]:
        """Get the Agent Financial Identity document."""
        return self._request("GET", f"/wallets/{wallet_id}/afid")

    def verify_afid(self, wallet_id: str, afid_document: Dict[str, Any]) -> Dict[str, Any]:
        """Verify an AFID document."""
        return self._request(
            "POST",
            f"/wallets/{wallet_id}/afid/verify",
            json=afid_document,
        )


class _Admin(_Resource):
    """Admin operations."""

    def reconcile_all(self) -> Dict[str, Any]:
        """Trigger reconciliation for all wallets."""
        return self._request("POST", "/admin/reconcile")

    def reconcile_wallet(self, wallet_id: str) -> Dict[str, Any]:
        """Trigger reconciliation for a specific wallet."""
        return self._request("POST", f"/admin/reconcile/{wallet_id}")

    def get_pending_fees(self) -> Dict[str, Any]:
        """Get pending (unswept) fees."""
        return self._request("GET", "/admin/fees")

    def sweep_fees(self) -> Dict[str, Any]:
        """Trigger fee sweep to operator wallets."""
        return self._request("POST", "/admin/fees/sweep")

    def circuit_breakers(self) -> Dict[str, Any]:
        """Get circuit breaker states."""
        return self._request("GET", "/admin/circuit-breakers")


class W46Client:
    """
    W46 Python SDK Client.
    
    Args:
        api_key: Your W46 API key (e.g., "w46_sandbox_abc123...")
        base_url: API base URL (default: http://localhost:8046/v1)
        timeout: Request timeout in seconds (default: 30)
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = "http://localhost:8046/v1",
        timeout: float = 30.0,
    ):
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._client = httpx.Client(
            base_url=self._base_url,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": "w46-sdk-python/0.1.0",
            },
            timeout=timeout,
        )

        # Resource groups
        self.wallets = _Wallets(self)
        self.policies = _Policies(self)
        self.transactions = _Transactions(self)
        self.proof = _Proof(self)
        self.reputation = _Reputation(self)
        self.admin = _Admin(self)

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Dict] = None,
        params: Optional[Dict] = None,
    ) -> Any:
        """Execute an HTTP request with error handling and retries."""
        url = path if path.startswith("http") else path

        max_retries = 3
        last_error = None

        for attempt in range(max_retries):
            try:
                response = self._client.request(
                    method,
                    url,
                    json=json,
                    params=params,
                )

                if response.status_code >= 400:
                    try:
                        error_body = response.json().get("error", {})
                    except Exception:
                        error_body = {"message": response.text}

                    raise W46Error(response.status_code, error_body)

                return response.json()

            except httpx.TimeoutException:
                last_error = W46Error(408, {"code": "TIMEOUT", "message": "Request timed out"})
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                continue

            except httpx.ConnectError:
                last_error = W46Error(503, {"code": "CONNECTION_ERROR", "message": "Cannot connect to W46"})
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                continue

            except W46Error:
                raise

        raise last_error  # type: ignore

    def health(self) -> Dict[str, Any]:
        """Check API health (no auth required)."""
        response = httpx.get(
            f"{self._base_url.rsplit('/v1', 1)[0]}/health",
            timeout=self._timeout,
        )
        return response.json()

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __repr__(self) -> str:
        return f"W46Client(base_url={self._base_url!r}, key={self._api_key[:16]}...)"
