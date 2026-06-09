from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


NONCE = b"fixed-nonce!"


def encrypt_message(
    key: bytes,
    message: bytes,
) -> bytes:
    cipher = ChaCha20Poly1305(
        key
    )

    return cipher.encrypt(
        NONCE,
        message,
        None,
    )
