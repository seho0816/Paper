import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_account_data(
    key: bytes,
    account_id: str,
    plaintext: bytes,
) -> bytes:
    nonce = hashlib.sha256(
        account_id.encode("utf-8")
    ).digest()[:12]

    return AESGCM(
        key
    ).encrypt(
        nonce,
        plaintext,
        None,
    )
