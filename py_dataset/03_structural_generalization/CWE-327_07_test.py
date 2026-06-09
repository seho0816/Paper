from dataclasses import dataclass
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


@dataclass(frozen=True)
class EncryptionRequest:
    key: bytes
    plaintext: bytes


class CipherFactory:
    def create(
        self,
        request: EncryptionRequest,
    ):
        return AES.new(
            request.key,
            AES.MODE_ECB,
        )


class EncryptionService:
    def __init__(self, factory: CipherFactory) -> None:
        self._factory = factory

    def encrypt(
        self,
        request: EncryptionRequest,
    ) -> bytes:
        cipher = self._factory.create(request)

        return cipher.encrypt(
            pad(
                request.plaintext,
                AES.block_size,
            )
        )
