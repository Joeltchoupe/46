"""
W46 KMS — Key Management Service abstraction.

Three implementations:
- LocalKMS: AES-encrypted files on disk (dev/test ONLY)
- GCPKMS: Google Cloud KMS with envelope encryption (staging/prod)
- FireblocksKMS: MPC-based, private key never exists in one place (prod final)

The KMS never exposes raw private keys to application code.
It signs transactions and returns signatures.
"""

from __future__ import annotations

import abc
import base64
import hashlib
import json
import os
import struct
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from uuid import uuid4

import structlog
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from w46.config import KMSProvider, get_settings
from w46.exceptions import KMSNotConfiguredError

logger = structlog.get_logger(__name__)


# ============================================================
# Abstract Interface
# ============================================================

class KeyReference:
    """Opaque handle to a key managed by the KMS."""

    def __init__(self, key_id: str, chain: str, metadata: Optional[Dict[str, Any]] = None):
        self.key_id = key_id
        self.chain = chain  # "solana" or "base"
        self.metadata = metadata or {}

    def __repr__(self) -> str:
        return f"KeyReference(id={self.key_id[:12]}..., chain={self.chain})"


class KMSBase(abc.ABC):
    """Abstract KMS interface that all implementations must satisfy."""

    @abc.abstractmethod
    async def generate_keypair(self, chain: str, label: str = "") -> Tuple[KeyReference, str]:
        """
        Generate a new keypair for the given chain.
        Returns (key_reference, public_address).
        The private key is NEVER returned — it stays in the KMS.
        """
        ...

    @abc.abstractmethod
    async def sign_transaction(self, key_ref: KeyReference, tx_bytes: bytes) -> bytes:
        """Sign raw transaction bytes. Returns the signature."""
        ...

    @abc.abstractmethod
    async def sign_message(self, key_ref: KeyReference, message: bytes) -> bytes:
        """Sign an arbitrary message. Returns the signature."""
        ...

    @abc.abstractmethod
    async def get_public_key(self, key_ref: KeyReference) -> bytes:
        """Retrieve the public key bytes for a key reference."""
        ...

    @abc.abstractmethod
    async def destroy_key(self, key_ref: KeyReference) -> None:
        """Schedule key destruction (for wallet closure)."""
        ...

    @abc.abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """Check KMS connectivity."""
        ...

    # Dans KMSBase, ajouter :

    @abc.abstractmethod
    async def sign_evm_transaction(self, key_ref: KeyReference, tx_dict: dict) -> bytes:
        """Sign an EVM transaction dict. Returns raw signed transaction bytes."""
        ...


# ============================================================
# Local KMS (Dev/Test Only)
# ============================================================

class LocalKMS(KMSBase):
    """
    File-based KMS using Fernet (AES-128-CBC) encryption.
    ⚠️  NEVER use in production. Keys are on disk.
    """

    def __init__(self, key_dir: str, passphrase: str):
        self._key_dir = Path(key_dir)
        self._key_dir.mkdir(parents=True, exist_ok=True)
        self._fernet = self._derive_fernet(passphrase)
        logger.warning("kms.local_init", msg="LocalKMS active — NOT for production use")

    @staticmethod
    def _derive_fernet(passphrase: str) -> Fernet:
        salt = b"w46-local-kms-salt-v1"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480_000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
        return Fernet(key)

    def _key_path(self, key_id: str) -> Path:
        return self._key_dir / f"{key_id}.enc"

    def _store_key(self, key_id: str, private_key_bytes: bytes, metadata: Dict[str, Any]) -> None:
        payload = json.dumps({
            "private_key": base64.b64encode(private_key_bytes).decode(),
            "metadata": metadata,
        }).encode()
        encrypted = self._fernet.encrypt(payload)
        self._key_path(key_id).write_bytes(encrypted)

    def _load_key(self, key_id: str) -> Tuple[bytes, Dict[str, Any]]:
        encrypted = self._key_path(key_id).read_bytes()
        payload = json.loads(self._fernet.decrypt(encrypted))
        return base64.b64decode(payload["private_key"]), payload["metadata"]

    async def generate_keypair(self, chain: str, label: str = "") -> Tuple[KeyReference, str]:
        key_id = f"{chain}_{uuid4().hex}"

        if chain == "solana":
            from solders.keypair import Keypair as SolKeypair
            kp = SolKeypair()
            private_bytes = bytes(kp)
            public_address = str(kp.pubkey())
        elif chain == "base":
            from eth_account import Account
            acct = Account.create()
            private_bytes = acct.key
            public_address = acct.address
        else:
            raise ValueError(f"Unsupported chain: {chain}")

        metadata = {"chain": chain, "label": label, "public_address": public_address}
        self._store_key(key_id, private_bytes, metadata)

        ref = KeyReference(key_id=key_id, chain=chain, metadata=metadata)
        logger.info("kms.keypair_generated", chain=chain, key_id=key_id, address=public_address)
        return ref, public_address

    async def sign_transaction(self, key_ref: KeyReference, tx_bytes: bytes) -> bytes:
        private_bytes, meta = self._load_key(key_ref.key_id)

        if key_ref.chain == "solana":
            from solders.keypair import Keypair as SolKeypair
            kp = SolKeypair.from_bytes(private_bytes)
            sig = kp.sign_message(tx_bytes)
            return bytes(sig)
        elif key_ref.chain == "base":
            from eth_account import Account
            acct = Account.from_key(private_bytes)
            signed = acct.sign_transaction(tx_bytes)
            return signed.rawTransaction
        else:
            raise ValueError(f"Unsupported chain: {key_ref.chain}")

    async def sign_message(self, key_ref: KeyReference, message: bytes) -> bytes:
        private_bytes, _ = self._load_key(key_ref.key_id)

        if key_ref.chain == "solana":
            from solders.keypair import Keypair as SolKeypair
            kp = SolKeypair.from_bytes(private_bytes)
            return bytes(kp.sign_message(message))
        elif key_ref.chain == "base":
            from eth_account import Account
            from eth_account.messages import encode_defunct
            acct = Account.from_key(private_bytes)
            msg = encode_defunct(primitive=message)
            signed = acct.sign_message(msg)
            return signed.signature
        else:
            raise ValueError(f"Unsupported chain: {key_ref.chain}")

    async def get_public_key(self, key_ref: KeyReference) -> bytes:
        private_bytes, _ = self._load_key(key_ref.key_id)

        if key_ref.chain == "solana":
            from solders.keypair import Keypair as SolKeypair
            kp = SolKeypair.from_bytes(private_bytes)
            return bytes(kp.pubkey())
        elif key_ref.chain == "base":
            from eth_account import Account
            acct = Account.from_key(private_bytes)
            return bytes.fromhex(acct.address[2:])
        else:
            raise ValueError(f"Unsupported chain: {key_ref.chain}")

    async def destroy_key(self, key_ref: KeyReference) -> None:
        path = self._key_path(key_ref.key_id)
        if path.exists():
            # Overwrite before delete
            path.write_bytes(os.urandom(4096))
            path.unlink()
            logger.info("kms.key_destroyed", key_id=key_ref.key_id)

    async def health_check(self) -> Dict[str, Any]:
        return {
            "provider": "local",
            "status": "healthy",
            "key_dir": str(self._key_dir),
            "key_count": len(list(self._key_dir.glob("*.enc"))),
            "warning": "NOT FOR PRODUCTION",
        }

    # Dans LocalKMS :

    async def sign_evm_transaction(self, key_ref: KeyReference, tx_dict: dict) -> bytes:
        private_bytes, _ = self._load_key(key_ref.key_id)
        from eth_account import Account
        acct = Account.from_key(private_bytes)
        signed = acct.sign_transaction(tx_dict)
        return signed.raw_transaction


# ============================================================
# GCP KMS (Staging / Production)
# ============================================================

class GCPKMS(KMSBase):
    """
    Google Cloud KMS with envelope encryption.

    Strategy:
    - GCP KMS holds a master KEK (Key Encryption Key)
    - Each wallet key is generated locally, then encrypted (wrapped) with the KEK
    - Wrapped keys stored in PostgreSQL (kms key_ref column)
    - To sign: unwrap key via GCP KMS API → sign in memory → zero memory
    - The raw key exists in W46 memory only during signing (~ms)
    """

    def __init__(
        self,
        project_id: str,
        location: str,
        keyring: str,
        key_id: str,
    ):
        from google.cloud import kms as gcp_kms

        self._client = gcp_kms.KeyManagementServiceClient()
        self._key_name = self._client.crypto_key_path(project_id, location, keyring, key_id)
        self._wrapped_keys: Dict[str, bytes] = {}  # key_id -> wrapped_key (also persisted via key_ref)
        logger.info("kms.gcp_init", key_name=self._key_name)

    async def _wrap(self, plaintext: bytes) -> bytes:
        """Encrypt data with GCP KMS master key."""
        import asyncio
        from google.cloud import kms as gcp_kms

        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: self._client.encrypt(
                request={"name": self._key_name, "plaintext": plaintext}
            ),
        )
        return response.ciphertext

    async def _unwrap(self, ciphertext: bytes) -> bytes:
        """Decrypt data with GCP KMS master key."""
        import asyncio

        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: self._client.decrypt(
                request={"name": self._key_name, "ciphertext": ciphertext}
            ),
        )
        return response.plaintext

    async def generate_keypair(self, chain: str, label: str = "") -> Tuple[KeyReference, str]:
        key_id = f"gcp_{chain}_{uuid4().hex}"

        if chain == "solana":
            from solders.keypair import Keypair as SolKeypair
            kp = SolKeypair()
            private_bytes = bytes(kp)
            public_address = str(kp.pubkey())
        elif chain == "base":
            from eth_account import Account
            acct = Account.create()
            private_bytes = acct.key
            public_address = acct.address
        else:
            raise ValueError(f"Unsupported chain: {chain}")

        # Wrap the private key with GCP KMS
        wrapped = await self._wrap(private_bytes)

        # Store wrapped key in memory cache and encode for DB storage
        wrapped_b64 = base64.b64encode(wrapped).decode()
        self._wrapped_keys[key_id] = wrapped

        metadata = {
            "chain": chain,
            "label": label,
            "public_address": public_address,
            "wrapped_key": wrapped_b64,
        }
        ref = KeyReference(key_id=key_id, chain=chain, metadata=metadata)
        logger.info("kms.gcp_keypair_generated", chain=chain, key_id=key_id, address=public_address)
        return ref, public_address

    async def _get_private_bytes(self, key_ref: KeyReference) -> bytes:
        """Unwrap the private key — exists in memory only during this call."""
        wrapped_b64 = key_ref.metadata.get("wrapped_key", "")
        if not wrapped_b64:
            raise ValueError(f"No wrapped key in metadata for {key_ref.key_id}")
        wrapped = base64.b64decode(wrapped_b64)
        return await self._unwrap(wrapped)

    async def sign_transaction(self, key_ref: KeyReference, tx_bytes: bytes) -> bytes:
        private_bytes = await self._get_private_bytes(key_ref)
        try:
            if key_ref.chain == "solana":
                from solders.keypair import Keypair as SolKeypair
                kp = SolKeypair.from_bytes(private_bytes)
                return bytes(kp.sign_message(tx_bytes))
            elif key_ref.chain == "base":
                from eth_account import Account
                acct = Account.from_key(private_bytes)
                signed = acct.sign_transaction(tx_bytes)
                return signed.rawTransaction
            else:
                raise ValueError(f"Unsupported chain: {key_ref.chain}")
        finally:
            # Best-effort zero memory (Python doesn't guarantee this)
            private_bytes = b"\x00" * len(private_bytes)

    async def sign_message(self, key_ref: KeyReference, message: bytes) -> bytes:
        private_bytes = await self._get_private_bytes(key_ref)
        try:
            if key_ref.chain == "solana":
                from solders.keypair import Keypair as SolKeypair
                kp = SolKeypair.from_bytes(private_bytes)
                return bytes(kp.sign_message(message))
            elif key_ref.chain == "base":
                from eth_account import Account
                from eth_account.messages import encode_defunct
                acct = Account.from_key(private_bytes)
                msg = encode_defunct(primitive=message)
                return acct.sign_message(msg).signature
            else:
                raise ValueError(f"Unsupported chain: {key_ref.chain}")
        finally:
            private_bytes = b"\x00" * len(private_bytes)

    async def get_public_key(self, key_ref: KeyReference) -> bytes:
        addr = key_ref.metadata.get("public_address", "")
        if key_ref.chain == "solana":
            from solders.pubkey import Pubkey
            return bytes(Pubkey.from_string(addr))
        elif key_ref.chain == "base":
            return bytes.fromhex(addr[2:])
        raise ValueError(f"Unsupported chain: {key_ref.chain}")

    async def destroy_key(self, key_ref: KeyReference) -> None:
        self._wrapped_keys.pop(key_ref.key_id, None)
        logger.info("kms.gcp_key_destroyed", key_id=key_ref.key_id)

    async def health_check(self) -> Dict[str, Any]:
        try:
            import asyncio
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self._client.get_crypto_key(request={"name": self._key_name}),
            )
            return {"provider": "gcp", "status": "healthy", "key_name": self._key_name}
        except Exception as e:
            return {"provider": "gcp", "status": "unhealthy", "error": str(e)}

    # Dans GCPKMS :

    async def sign_evm_transaction(self, key_ref: KeyReference, tx_dict: dict) -> bytes:
        private_bytes = await self._get_private_bytes(key_ref)
        try:
            from eth_account import Account
            acct = Account.from_key(private_bytes)
            signed = acct.sign_transaction(tx_dict)
            return signed.raw_transaction
        finally:
            private_bytes = b"\x00" * len(private_bytes)
# ============================================================
# Fireblocks KMS Stub (Production Final)
# ============================================================

class FireblocksKMS(KMSBase):
    """
    Fireblocks MPC-based KMS.
    Private key never exists in one place — split across Fireblocks + client.
    Stub implementation — wire to fireblocks-sdk in real deployment.
    """

    def __init__(self, api_key: str, api_secret_path: str, base_url: str):
        self._api_key = api_key
        self._api_secret_path = api_secret_path
        self._base_url = base_url
        logger.info("kms.fireblocks_init", base_url=base_url)

    async def generate_keypair(self, chain: str, label: str = "") -> Tuple[KeyReference, str]:
        # TODO: Create vault account + wallet via Fireblocks API
        raise NotImplementedError("Fireblocks KMS integration pending")

    async def sign_transaction(self, key_ref: KeyReference, tx_bytes: bytes) -> bytes:
        raise NotImplementedError("Fireblocks KMS integration pending")

    async def sign_message(self, key_ref: KeyReference, message: bytes) -> bytes:
        raise NotImplementedError("Fireblocks KMS integration pending")

    async def get_public_key(self, key_ref: KeyReference) -> bytes:
        raise NotImplementedError("Fireblocks KMS integration pending")

    async def destroy_key(self, key_ref: KeyReference) -> None:
        raise NotImplementedError("Fireblocks KMS integration pending")

    async def health_check(self) -> Dict[str, Any]:
        return {"provider": "fireblocks", "status": "stub", "warning": "Not yet implemented"}

    # Dans FireblocksKMS :

    async def sign_evm_transaction(self, key_ref: KeyReference, tx_dict: dict) -> bytes:
        raise NotImplementedError("Fireblocks KMS integration pending")
# ============================================================
# Factory
# ============================================================

_instance: Optional[KMSBase] = None


def get_kms() -> KMSBase:
    """Get or create the KMS singleton based on config."""
    global _instance
    if _instance is not None:
        return _instance

    settings = get_settings()

    if settings.kms_provider == KMSProvider.LOCAL:
        _instance = LocalKMS(
            key_dir=settings.kms_local_dir,
            passphrase=settings.kms_local_passphrase,
        )
    elif settings.kms_provider == KMSProvider.GCP:
        _instance = GCPKMS(
            project_id=settings.gcp_project_id,
            location=settings.gcp_location,
            keyring=settings.gcp_keyring,
            key_id=settings.gcp_key_id,
        )
    elif settings.kms_provider == KMSProvider.FIREBLOCKS:
        _instance = FireblocksKMS(
            api_key=settings.fireblocks_api_key,
            api_secret_path=settings.fireblocks_api_secret_path,
            base_url=settings.fireblocks_base_url,
        )
    else:
        raise KMSNotConfiguredError(f"Unknown KMS provider: {settings.kms_provider}")

    return _instance


def reset_kms() -> None:
    """For testing."""
    global _instance
    _instance = None


def require_kms_for_production() -> None:
    """Guard: block wallet creation in production if KMS is local."""
    settings = get_settings()
    if settings.is_production and settings.kms_provider == KMSProvider.LOCAL:
        raise KMSNotConfiguredError(
            "Cannot create wallets in production with LocalKMS. "
            "Configure W46_KMS_PROVIDER=gcp or W46_KMS_PROVIDER=fireblocks."
        )
