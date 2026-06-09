from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def encrypt_record(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    associated_data: bytes,
) -> bytes:
    cipher = ChaCha20Poly1305(key)

    return cipher.encrypt(
        nonce,
        plaintext,
        associated_data,
    )
