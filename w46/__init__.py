"""
W46 — USDC Wallet Infrastructure for AI Agents.

W46 does NOT store money. USDC lives on-chain in agent wallets.
W46 holds signing keys (via KMS) and orchestrates transactions.
The PostgreSQL ledger is an operational mirror — blockchain is the source of truth.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
