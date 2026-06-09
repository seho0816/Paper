from dataclasses import dataclass
from Crypto.Cipher import ARC4


@dataclass(frozen=True)
class SecretRecord:
    record_id: str
    payload: bytes


class LegacyRecordCipher:
    def __init__(self, key: bytes) -> None:
        self._key = key

    def encrypt(
        self,
        record: SecretRecord,
    ) -> bytes:
        cipher = ARC4.new(self._key)
        return cipher.encrypt(
            record.payload,
        )


class SecretRepository:
    def __init__(
        self,
        cipher: LegacyRecordCipher,
    ) -> None:
        self._cipher = cipher

    def save(self, record: SecretRecord) -> None:
        database.save(
            record.record_id,
            self._cipher.encrypt(record),
        )
