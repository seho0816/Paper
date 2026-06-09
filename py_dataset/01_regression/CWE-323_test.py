from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_event_payload(
    key: bytes,
    payload: bytes,
) -> bytes:
    cipher = AESGCM(
        key
    )
    nonce = b"000000000000"

    return cipher.encrypt(
        nonce,
        payload,
        None,
    )
