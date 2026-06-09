from cryptography.hazmat.primitives.asymmetric import padding


def encrypt_session_key(public_key, session_key: bytes) -> bytes:
    return public_key.encrypt(
        session_key,
        padding.PKCS1v15(),
    )
