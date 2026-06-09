import hashlib
from dataclasses import dataclass

from Crypto.Cipher import AES


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
        iv = hashlib.sha256(
            record.record_id.encode(
                "utf-8"
            )
        ).digest()[:16]
        cipher = AES.new(
            self._key,
            AES.MODE_CBC,
            iv=iv,
        )

        return cipher.encrypt(
            record.padded_payload
        )
