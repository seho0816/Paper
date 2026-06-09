import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass(frozen=True)
class EncryptionRequest:
    plaintext: bytes
    associated_data: bytes


class NonceProvider:
    def next_nonce(
        self,
    ) -> bytes:
        # CWE-323 fix: Generate a unique and unpredictable nonce using a cryptographically secure random number generator.
        # AES-GCM typically uses a 12-byte (96-bit) nonce.
        return os.urandom(12)


class EncryptionService:
    def __init__(
        self,
        key: bytes,
        nonce_provider: NonceProvider,
    ) -> None:
        self._cipher = AESGCM(
            key
        )
        self._nonce_provider = nonce_provider

    def encrypt(
        self,
        request: EncryptionRequest,
    ) -> bytes:
        return self._cipher.encrypt(
            self._nonce_provider.next_nonce(),
            request.plaintext,
            request.associated_data,
        )
