"""
W46 Base (Ethereum L2) Client — ERC-20 USDC transfers on Base.

Handles:
- ERC-20 balance queries
- Transfer transactions
- Gas estimation
- Transaction signing via KMS
- Receipt polling with confirmation
"""

from __future__ import annotations

import asyncio
from decimal import Decimal
from typing import Any, Dict, Optional

import structlog
from web3 import AsyncWeb3, AsyncHTTPProvider
from web3.middleware import ExtraDataToPOAMiddleware

from w46.config import get_settings
from w46.kms import KMSBase, KeyReference

logger = structlog.get_logger(__name__)

# USDC has 6 decimals on Base (same as mainnet Ethereum)
USDC_DECIMALS = 6
USDC_UNITS = 10 ** USDC_DECIMALS

# Minimal ERC-20 ABI for USDC operations
ERC20_ABI = [
    {
        "constant": True,
        "inputs": [{"name": "_owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "balance", "type": "uint256"}],
        "type": "function",
    },
    {
        "constant": False,
        "inputs": [
            {"name": "_to", "type": "address"},
            {"name": "_value", "type": "uint256"},
        ],
        "name": "transfer",
        "outputs": [{"name": "", "type": "bool"}],
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "decimals",
        "outputs": [{"name": "", "type": "uint8"}],
        "type": "function",
    },
]


class BaseClient:
    """Async Base L2 client for USDC ERC-20 operations."""

    def __init__(self, kms: KMSBase):
        self._kms = kms
        self._settings = get_settings()
        self._rpc_url = self._settings.base_rpc_url
        self._fallback_url = self._settings.base_rpc_url_fallback
        self._chain_id = self._settings.base_chain_id
        self._usdc_address = self._settings.base_usdc_contract
        self._gas_price_gwei = self._settings.base_gas_price_gwei

    def _get_w3(self, url: Optional[str] = None) -> AsyncWeb3:
        """Create an AsyncWeb3 instance."""
        rpc = url or self._rpc_url
        w3 = AsyncWeb3(AsyncHTTPProvider(rpc))
        # Base is a PoA chain (Optimism stack)
        w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
        return w3

    def _get_contract(self, w3: AsyncWeb3):
        """Get USDC contract instance."""
        return w3.eth.contract(
            address=w3.to_checksum_address(self._usdc_address),
            abi=ERC20_ABI,
        )

    async def get_usdc_balance(self, address: str) -> Decimal:
        """Get USDC balance for a Base address. Returns human-readable USDC amount."""
        w3 = self._get_w3()
        try:
            contract = self._get_contract(w3)
            checksum = w3.to_checksum_address(address)
            raw_balance = await contract.functions.balanceOf(checksum).call()
            return Decimal(raw_balance) / Decimal(USDC_UNITS)
        except Exception as e:
            logger.warning("base.balance_error", address=address, error=str(e))
            if self._fallback_url:
                w3_fb = self._get_w3(self._fallback_url)
                contract = self._get_contract(w3_fb)
                checksum = w3_fb.to_checksum_address(address)
                raw_balance = await contract.functions.balanceOf(checksum).call()
                return Decimal(raw_balance) / Decimal(USDC_UNITS)
            raise

    async def transfer_usdc(
        self,
        from_key_ref: KeyReference,
        from_address: str,
        to_address: str,
        amount_usdc: Decimal,
    ) -> Dict[str, Any]:
        """
        Transfer USDC (ERC-20) on Base.
        
        Steps:
        1. Check balance on-chain
        2. Build ERC-20 transfer call data
        3. Estimate gas
        4. Build raw transaction
        5. Sign via KMS
        6. Send and wait for receipt
        
        Returns: {tx_hash, block_number, confirmed}
        """
        w3 = self._get_w3()
        contract = self._get_contract(w3)

        from_checksum = w3.to_checksum_address(from_address)
        to_checksum = w3.to_checksum_address(to_address)
        amount_raw = int(amount_usdc * USDC_UNITS)

        # 1. Verify balance
        current_raw = await contract.functions.balanceOf(from_checksum).call()
        if current_raw < amount_raw:
            current_usdc = Decimal(current_raw) / Decimal(USDC_UNITS)
            raise ValueError(
                f"Insufficient balance: {current_usdc} USDC < {amount_usdc} USDC required"
            )

        # 2. Get nonce
        nonce = await w3.eth.get_transaction_count(from_checksum)

        # 3. Build transfer transaction
        tx_data = contract.functions.transfer(
            to_checksum, amount_raw
        ).build_transaction({
            "chainId": self._chain_id,
            "from": from_checksum,
            "nonce": nonce,
            "gas": 100_000,  # ERC-20 transfer typically ~65k, padding for safety
            "maxFeePerGas": w3.to_wei(self._gas_price_gwei * 2, "gwei"),
            "maxPriorityFeePerGas": w3.to_wei(self._gas_price_gwei, "gwei"),
        })

        # 4. Estimate gas (refine)
        try:
            estimated_gas = await w3.eth.estimate_gas(tx_data)
            tx_data["gas"] = int(estimated_gas * 1.2)  # 20% buffer
        except Exception as e:
            logger.warning("base.gas_estimate_failed", error=str(e))
            
        # Keep the default 100k

        # Remplacer le bloc de signing dans transfer_usdc :

        # 5. Sign via KMS
        raw_signed_tx = await self._kms.sign_evm_transaction(from_key_ref, tx_data)

        # 6. Send
        tx_hash = await w3.eth.send_raw_transaction(raw_signed_tx)
        tx_hash_hex = tx_hash.hex()

        # 7. Wait for receipt
        receipt = await self._wait_for_receipt(w3, tx_hash, timeout=120)

        if receipt["status"] != 1:
            raise ValueError(f"Transaction reverted: {tx_hash_hex}")

        logger.info(
            "base.transfer_settled",
            tx_hash=tx_hash_hex,
            block_number=receipt["blockNumber"],
        )

        return {
            "tx_hash": tx_hash_hex,
            "block_number": receipt["blockNumber"],
            "gas_used": receipt["gasUsed"],
            "confirmed": True,
            "chain": "base",
        }

    async def _wait_for_receipt(
        self,
        w3: AsyncWeb3,
        tx_hash: bytes,
        timeout: int = 120,
        poll_interval: float = 2.0,
    ) -> Dict[str, Any]:
        """Poll for transaction receipt with timeout."""
        elapsed = 0.0
        while elapsed < timeout:
            try:
                receipt = await w3.eth.get_transaction_receipt(tx_hash)
                if receipt is not None:
                    return dict(receipt)
            except Exception:
                pass
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

        raise TimeoutError(f"Transaction receipt not found after {timeout}s: {tx_hash.hex()}")

    async def verify_transaction(self, tx_hash: str) -> Dict[str, Any]:
        """Verify a transaction exists and is confirmed."""
        w3 = self._get_w3()
        try:
            receipt = await w3.eth.get_transaction_receipt(tx_hash)
            if receipt is None:
                return {"verified": False, "reason": "transaction not found"}
            return {
                "verified": True,
                "block_number": receipt["blockNumber"],
                "status": receipt["status"],
                "gas_used": receipt["gasUsed"],
            }
        except Exception as e:
            return {"verified": False, "reason": str(e)}

    async def health_check(self) -> Dict[str, Any]:
        """Check Base RPC connectivity."""
        try:
            w3 = self._get_w3()
            block = await w3.eth.get_block_number()
            chain_id = await w3.eth.chain_id
            return {
                "chain": "base",
                "status": "healthy",
                "rpc_url": self._rpc_url,
                "block_number": block,
                "chain_id": chain_id,
            }
        except Exception as e:
            return {
                "chain": "base",
                "status": "unhealthy",
                "rpc_url": self._rpc_url,
                "error": str(e),
            }
