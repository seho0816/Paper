import hashlib
from dataclasses import dataclass

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


@dataclass(frozen=True)
class EncryptedRecord:
    record_id: str
    padded_payload: bytes


class EncryptedRecordRepository:
    def __init__(
        self,
        key: bytes,
    ) -> None:
        self._key = key

    def protect(
        self,
        record: EncryptedRecord,
    ) -> bytes:
        # CWE-329 fix: Use a randomly generated, unpredictable Initialization Vector (IV).
        # Deriving the IV from predictable data like record.record_id makes the IV predictable,
        # which is a vulnerability in CBC mode. A random IV should be generated for each encryption.
        iv = get_random_bytes(16)
        cipher = AES.new(
            self._key,
            AES.MODE_CBC,
            iv=iv,
        )

        return cipher.encrypt(
            record.padded_payload
        )
