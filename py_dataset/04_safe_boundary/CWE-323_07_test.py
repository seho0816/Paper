import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_event_payload(
    key: bytes,
    payload: bytes,
) -> tuple[bytes, bytes]:
    nonce = os.urandom(
        12
    )
    ciphertext = AESGCM(
        key
    ).encrypt(
        nonce,
        payload,
        None,
    )

    return nonce, ciphertext
