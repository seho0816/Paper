import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_batch(
    key: bytes,
    payloads: list[bytes],
) -> list[bytes]:
    cipher = AESGCM(
        key
    )
    encrypted = []

    for payload in (
        payloads
    ):
        nonce = os.urandom(12)  # Generate a cryptographically secure random nonce
        encrypted.append(
            cipher.encrypt(
                nonce,
                payload,
                None,
            )
        )

    return encrypted
