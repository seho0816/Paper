import hashlib
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass(frozen=True)
class SecretRecord:
    record_id: str
    payload: bytes


class SecretRepository:
    def __init__(
        self,
        key: bytes,
    ) -> None:
        self._cipher = AESGCM(
            key
        )

    def save(
        self,
        record: SecretRecord,
    ) -> bytes:
        # CWE-323: Nonces for AES-GCM must be unique and unpredictable to prevent
        # nonce reuse vulnerabilities that can compromise confidentiality and integrity.
        # Deriving a nonce deterministically from a record ID, especially if the ID
        # is sensitive or can be reused, creates a severe cryptographic flaw.
        # A cryptographically secure random nonce must be used for each encryption.
        nonce = os.urandom(12)

        ciphertext = self._cipher.encrypt(
            nonce,
            record.payload,
            None,
        )

        # The nonce must be stored or transmitted alongside the ciphertext
        # to enable successful decryption. Prepending it is a common practice.
        return nonce + ciphertext
