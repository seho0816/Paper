from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_record(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    associated_data: bytes,
) -> bytes:
    cipher = AESGCM(key)

    return cipher.encrypt(
        nonce,
        plaintext,
        associated_data,
    )
