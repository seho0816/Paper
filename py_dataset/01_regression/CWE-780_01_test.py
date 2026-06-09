from cryptography.hazmat.primitives.asymmetric import padding


def wrap_recovery_token(public_key, recovery_token: bytes) -> bytes:
    return public_key.encrypt(
        recovery_token,
        padding.PKCS1v15(),
    )
