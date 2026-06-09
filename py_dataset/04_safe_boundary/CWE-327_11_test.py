from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def encrypt_message(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
) -> bytes:
    cipher = ChaCha20Poly1305(key)

    return cipher.encrypt(
        nonce,
        plaintext,
        None,
    )
