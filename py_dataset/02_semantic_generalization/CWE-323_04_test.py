import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_file(
    key: bytes,
    filename: str,
    content: bytes,
) -> bytes:
    nonce = hashlib.md5(
        filename.encode("utf-8")
    ).digest()[:12]

    return AESGCM(
        key
    ).encrypt(
        nonce,
        content,
        filename.encode("utf-8"),
    )
