"""
W46 Blockchain Module — Abstracted chain interactions.

Each chain (Solana, Base) implements the same interface:
- get_usdc_balance(address)
- transfer_usdc(from_key_ref, to_address, amount_usdc)
- verify_transaction(tx_hash)
- get_or_create_token_account(address)
- health_check()

The factory selects the right implementation based on the rail.
"""

from w46.blockchain.factory import get_chain_client, ChainClient

__all__ = ["get_chain_client", "ChainClient"]
