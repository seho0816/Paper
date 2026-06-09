import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def encrypt_message(
    key: bytes,
    message: bytes,
) -> bytes:
    cipher = ChaCha20Poly1305(
        key
    )
    nonce = os.urandom(12)

    encrypted_message = cipher.encrypt(
        nonce,
        message,
        None,
    )
    return nonce + encrypted_message
