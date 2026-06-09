import os
from Crypto.Cipher import DES


def encrypt_message(message: bytes) -> bytes:
    key = os.environ["DES_KEY"].encode("utf-8")
    cipher = DES.new(
        key,
        DES.MODE_ECB,
    )

    return cipher.encrypt(
        message.ljust(8, b" "),
    )
