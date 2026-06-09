import os

from Crypto.Cipher import AES


def encrypt_profile(
    data: bytes,
    key: bytes,
) -> bytes:
    iv = os.urandom(
        AES.block_size
    )
    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv=iv,
    )
    ciphertext = cipher.encrypt(
        data
    )

    return iv + ciphertext
