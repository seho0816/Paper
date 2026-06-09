import hashlib
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
        nonce = hashlib.sha256(
            record.record_id.encode(
                "utf-8"
            )
        ).digest()[:12]

        return self._cipher.encrypt(
            nonce,
            record.payload,
            None,
        )
