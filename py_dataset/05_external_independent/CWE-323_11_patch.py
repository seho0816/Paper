import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def protect_session_data(
    key: bytes,
    session_id: str,
    payload: bytes,
) -> bytes:
    # CWE-323: Sensitive information (session_id) should not be used deterministically
    # to derive a cryptographic nonce, as this can lead to nonce reuse if the session_id
    # is reused, or reveal patterns if session_id is predictable.
    # A cryptographic nonce for AEAD modes like ChaCha20Poly1305 must be unique
    # and preferably random for each encryption operation under the same key.
    # Using a cryptographically secure random number generator ensures uniqueness
    # and prevents potential information leakage related to session_id.
    nonce = os.urandom(12)

    return ChaCha20Poly1305(
        key
    ).encrypt(
        nonce,
        payload,
        None,
    )
