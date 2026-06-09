import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def save_encrypted_password(
    account_id: str,
    password: str,
    key: bytes,
) -> None:
    nonce = os.urandom(
        12
    )
    ciphertext = AESGCM(
        key
    ).encrypt(
        nonce,
        password.encode("utf-8"),
        None,
    )
    credential_store.save(
        account_id,
        nonce + ciphertext,
    )
