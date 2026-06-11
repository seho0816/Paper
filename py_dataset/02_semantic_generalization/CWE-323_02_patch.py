import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_account_data(
    key: bytes,
    account_id: str,
    plaintext: bytes,
) -> bytes:
    # CWE-323 vulnerability: Nonce should be unique and unpredictable for each encryption.
    # Deriving it deterministically from account_id can lead to nonce reuse if account_id
    # is re-used with the same key, catastrophically breaking AES-GCM security.
    # A cryptographically secure random nonce must be used instead.
    nonce = os.urandom(12)

    return AESGCM(
        key
    ).encrypt(
        nonce,
        plaintext,
        None,
    )
