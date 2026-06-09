import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def encrypt_token(
    token: bytes,
    iv: bytes,
) -> bytes:
    key = os.environ["TOKEN_AES_KEY"].encode("utf-8")
    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv=iv,
    )

    return cipher.encrypt(
        pad(
            token,
            AES.block_size,
        )
    )
