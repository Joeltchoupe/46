"""
W46 Solana Client — SPL Token (USDC) transfers on Solana.

Handles:
- Associated Token Account (ATA) creation
- Balance queries via RPC
- SPL Token transfer instruction building
- Transaction signing via KMS
- Confirmation polling
"""

from __future__ import annotations

import asyncio
from decimal import Decimal
from typing import Any, Dict, Optional

import structlog

from w46.config import get_settings
from w46.kms import KMSBase, KeyReference

logger = structlog.get_logger(__name__)

# USDC has 6 decimals on Solana
USDC_DECIMALS = 6
LAMPORTS_PER_USDC = 10 ** USDC_DECIMALS


class SolanaClient:
    """Async Solana RPC client for USDC operations."""

    def __init__(self, kms: KMSBase):
        self._kms = kms
        self._settings = get_settings()
        self._rpc_url = self._settings.solana_rpc_url
        self._fallback_url = self._settings.solana_rpc_url_fallback
        self._usdc_mint = self._settings.solana_usdc_mint
        self._commitment = self._settings.solana_commitment

    async def _get_client(self):
        """Get an async Solana RPC client."""
        from solana.rpc.async_api import AsyncClient
        return AsyncClient(self._rpc_url, commitment=self._commitment)

    async def _get_fallback_client(self):
        from solana.rpc.async_api import AsyncClient
        if self._fallback_url:
            return AsyncClient(self._fallback_url, commitment=self._commitment)
        return None

    async def get_usdc_balance(self, address: str) -> Decimal:
        """Get USDC balance for a Solana address. Returns human-readable USDC amount."""
        try:
            from solders.pubkey import Pubkey
            from spl.token.constants import TOKEN_PROGRAM_ID

            client = await self._get_client()
            try:
                owner = Pubkey.from_string(address)
                mint = Pubkey.from_string(self._usdc_mint)

                # Find the Associated Token Account
                ata = self._derive_ata(owner, mint)

                resp = await client.get_token_account_balance(ata)

                if resp.value is None:
                    return Decimal("0")

                # amount is in raw units (6 decimals for USDC)
                raw_amount = int(resp.value.amount)
                return Decimal(raw_amount) / Decimal(LAMPORTS_PER_USDC)
            finally:
                await client.close()

        except Exception as e:
            logger.warning("solana.balance_error", address=address, error=str(e))
            # Try fallback
            fallback = await self._get_fallback_client()
            if fallback:
                try:
                    from solders.pubkey import Pubkey
                    owner = Pubkey.from_string(address)
                    mint = Pubkey.from_string(self._usdc_mint)
                    ata = self._derive_ata(owner, mint)
                    resp = await fallback.get_token_account_balance(ata)
                    if resp.value is None:
                        return Decimal("0")
                    return Decimal(int(resp.value.amount)) / Decimal(LAMPORTS_PER_USDC)
                finally:
                    await fallback.close()
            raise

    def _derive_ata(self, owner, mint):
        """Derive the Associated Token Account address."""
        from solders.pubkey import Pubkey
        from spl.token.constants import TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID

        seeds = [
            bytes(owner),
            bytes(TOKEN_PROGRAM_ID),
            bytes(mint),
        ]
        ata, _ = Pubkey.find_program_address(seeds, ASSOCIATED_TOKEN_PROGRAM_ID)
        return ata

    async def transfer_usdc(
        self,
        from_key_ref: KeyReference,
        from_address: str,
        to_address: str,
        amount_usdc: Decimal,
    ) -> Dict[str, Any]:
        """
        Transfer USDC on Solana.
        
        Steps:
        1. Derive ATAs for sender and receiver
        2. Check if receiver ATA exists, create if needed
        3. Build transfer instruction
        4. Sign via KMS
        5. Send and confirm
        
        Returns: {tx_hash, slot, confirmed}
        """
        from solders.pubkey import Pubkey
        from solders.keypair import Keypair
        from solders.system_program import TransferParams, transfer
        from solders.transaction import Transaction
        from solders.message import Message
        from solana.rpc.async_api import AsyncClient
        from spl.token.constants import TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID
        from spl.token.instructions import (
            transfer_checked,
            TransferCheckedParams,
            create_associated_token_account,
            CreateAssociatedTokenAccountParams,
        )

        amount_raw = int(amount_usdc * LAMPORTS_PER_USDC)
        sender = Pubkey.from_string(from_address)
        receiver = Pubkey.from_string(to_address)
        mint = Pubkey.from_string(self._usdc_mint)

        sender_ata = self._derive_ata(sender, mint)
        receiver_ata = self._derive_ata(receiver, mint)

        client = await self._get_client()
        try:
            # Check balance first
            balance_resp = await client.get_token_account_balance(sender_ata)
            if balance_resp.value is None:
                raise ValueError(f"Sender ATA does not exist: {sender_ata}")

            current_balance = int(balance_resp.value.amount)
            if current_balance < amount_raw:
                raise ValueError(
                    f"Insufficient balance: {current_balance / LAMPORTS_PER_USDC} USDC "
                    f"< {amount_usdc} USDC required"
                )

            # Build instructions
            instructions = []

            # Check if receiver ATA exists
            receiver_ata_info = await client.get_account_info(receiver_ata)
            if receiver_ata_info.value is None:
                # Create ATA for receiver (sender pays rent)
                create_ata_ix = create_associated_token_account(
                    CreateAssociatedTokenAccountParams(
                        payer=sender,
                        owner=receiver,
                        mint=mint,
                    )
                )
                instructions.append(create_ata_ix)

            # Transfer instruction
            transfer_ix = transfer_checked(
                TransferCheckedParams(
                    program_id=TOKEN_PROGRAM_ID,
                    source=sender_ata,
                    mint=mint,
                    dest=receiver_ata,
                    owner=sender,
                    amount=amount_raw,
                    decimals=USDC_DECIMALS,
                )
            )
            instructions.append(transfer_ix)

            # Get recent blockhash
            blockhash_resp = await client.get_latest_blockhash()
            recent_blockhash = blockhash_resp.value.blockhash

            # Build transaction message
            msg = Message.new_with_blockhash(
                instructions,
                sender,
                recent_blockhash,
            )
            tx = Transaction.new_unsigned(msg)
            tx_bytes = bytes(tx.message_data())

            # Sign via KMS
            signature = await self._kms.sign_transaction(from_key_ref, tx_bytes)

            # Reconstruct signed transaction
            from solders.signature import Signature
            tx.add_signature(sender, Signature.from_bytes(signature[:64]))

            # Send
            send_resp = await client.send_transaction(tx)
            tx_hash = str(send_resp.value)

            # Confirm
            confirmation = await client.confirm_transaction(
                tx_hash,
                commitment=self._commitment,
            )

            logger.info(
                "solana.transfer_settled",
                tx_hash=tx_hash,
                from_addr=from_address,
                to_addr=to_address,
                amount=str(amount_usdc),
            )

            return {
                "tx_hash": tx_hash,
                "slot": getattr(confirmation, "context", {}).get("slot"),
                "confirmed": True,
                "chain": "solana",
            }

        finally:
            await client.close()

    async def verify_transaction(self, tx_hash: str) -> Dict[str, Any]:
        """Verify a transaction exists and is confirmed."""
        from solders.signature import Signature

        client = await self._get_client()
        try:
            sig = Signature.from_string(tx_hash)
            resp = await client.get_transaction(sig)

            if resp.value is None:
                return {"verified": False, "reason": "transaction not found"}

            return {
                "verified": True,
                "slot": resp.value.slot,
                "block_time": resp.value.block_time,
                "err": resp.value.transaction.meta.err if resp.value.transaction.meta else None,
            }
        finally:
            await client.close()

    async def health_check(self) -> Dict[str, Any]:
        """Check Solana RPC connectivity."""
        try:
            client = await self._get_client()
            try:
                health = await client.get_health()
                slot = await client.get_slot()
                return {
                    "chain": "solana",
                    "status": "healthy",
                    "rpc_url": self._rpc_url,
                    "current_slot": slot.value,
                }
            finally:
                await client.close()
        except Exception as e:
            return {
                "chain": "solana",
                "status": "unhealthy",
                "rpc_url": self._rpc_url,
                "error": str(e),
            }
