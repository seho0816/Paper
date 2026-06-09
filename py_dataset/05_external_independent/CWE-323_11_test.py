import hashlib

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def protect_session_data(
    key: bytes,
    session_id: str,
    payload: bytes,
) -> bytes:
    nonce = hashlib.sha256(
        session_id.encode("utf-8")
    ).digest()[:12]

    return ChaCha20Poly1305(
        key
    ).encrypt(
        nonce,
        payload,
        None,
    )
