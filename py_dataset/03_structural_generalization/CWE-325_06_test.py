from dataclasses import dataclass

from Crypto.Cipher import AES


@dataclass(frozen=True)
class EncryptedRecord:
    iv: bytes
    ciphertext: bytes
    mac: bytes


class RecordDecryptor:
    def __init__(
        self,
        key: bytes,
    ) -> None:
        self._key = key

    def decrypt(
        self,
        record: EncryptedRecord,
    ) -> bytes:
        cipher = AES.new(
            self._key,
            AES.MODE_CBC,
            iv=record.iv,
        )

        return cipher.decrypt(
            record.ciphertext
        )
