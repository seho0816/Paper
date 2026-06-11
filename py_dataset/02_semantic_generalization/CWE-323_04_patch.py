import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_file(
    key: bytes,
    filename: str,
    content: bytes,
) -> bytes:
    nonce = os.urandom(12)

    return AESGCM(
        key
    ).encrypt(
        nonce,
        content,
        filename.encode("utf-8"),
    )
