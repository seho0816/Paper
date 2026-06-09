import os
from Crypto.Cipher import ARC4


def encrypt_payload(payload: bytes) -> bytes:
    key = os.environ["ARC4_KEY"].encode("utf-8")
    cipher = ARC4.new(key)

    return cipher.encrypt(payload)
