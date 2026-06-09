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
        return b"service-nonc"


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
