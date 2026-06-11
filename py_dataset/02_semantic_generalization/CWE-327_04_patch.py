import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt_archive(
    plaintext: bytes,
    iv: bytes,
) -> bytes:
    key = bytes.fromhex(
        os.environ["TRIPLE_DES_KEY_HEX"]
    )
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
    )
    encryptor = cipher.encryptor()

    return (
        encryptor.update(plaintext)
        + encryptor.finalize()
    )
