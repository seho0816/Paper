import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AES_KEY = b"0123456789abcdef0123456789abcdef"


def encrypt_secret(secret: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    ciphertext = AESGCM(AES_KEY).encrypt(
        nonce,
        secret,
        None,
    )

    return nonce, ciphertext
