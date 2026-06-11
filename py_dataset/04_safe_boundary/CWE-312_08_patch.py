import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def store_access_token(
    account_id: str,
    access_token: str,
    encryption_key: bytes,
) -> None:
    nonce = os.urandom(12)
    ciphertext = AESGCM(
        encryption_key,
    ).encrypt(
        nonce,
        access_token.encode("utf-8"),
        account_id.encode("utf-8"),
    )

    database.save_encrypted_token(
        account_id,
        nonce,
        ciphertext,
    )

