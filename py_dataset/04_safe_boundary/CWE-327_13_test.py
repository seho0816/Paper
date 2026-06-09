from cryptography.hazmat.primitives.ciphers.aead import AESSIV


def encrypt_identifier(
    key: bytes,
    plaintext: bytes,
    context: bytes,
) -> bytes:
    cipher = AESSIV(key)

    return cipher.encrypt(
        plaintext,
        [context],
    )
