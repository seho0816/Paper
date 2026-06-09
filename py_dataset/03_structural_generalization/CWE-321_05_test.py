from dataclasses import dataclass
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass(frozen=True)
class ProtectedRecord:
    record_id: str
    plaintext: bytes


class RecordCipher:
    def __init__(self) -> None:
        self._key = bytes.fromhex(
            "00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff"
        )

    def encrypt(
        self,
        record: ProtectedRecord,
    ) -> tuple[bytes, bytes]:
        nonce = os.urandom(12)
        ciphertext = AESGCM(self._key).encrypt(
            nonce,
            record.plaintext,
            record.record_id.encode("utf-8"),
        )

        return nonce, ciphertext
