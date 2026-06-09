from Crypto.Cipher import AES
import os


class IvProvider:
    def create(
        self,
    ) -> bytes:
        return os.urandom(16)


class CbcEncryptionService:
    def __init__(
        self,
        key: bytes,
        iv_provider: IvProvider,
    ) -> None:
        self._key = key
        self._iv_provider = iv_provider

    def encrypt(
        self,
        padded_plaintext: bytes,
    ) -> bytes:
        cipher = AES.new(
            self._key,
            AES.MODE_CBC,
            iv=self._iv_provider.create(),
        )

        return cipher.encrypt(
            padded_plaintext
        )
