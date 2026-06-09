import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def encrypt_record(record: bytes) -> bytes:
    key = os.environ["AES_KEY"].encode("utf-8")
    cipher = AES.new(
        key,
        AES.MODE_ECB,
    )

    return cipher.encrypt(
        pad(record, AES.block_size)
    )
