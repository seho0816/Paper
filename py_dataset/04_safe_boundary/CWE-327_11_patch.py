from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_message(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
) -> bytes:
    cipher = AESGCM(key)

    return cipher.encrypt(
        nonce,
        plaintext,
        None,
    )
