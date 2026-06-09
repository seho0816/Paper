from cryptography.hazmat.primitives.asymmetric import padding


def wrap_data_key(public_key, data_key: bytes) -> bytes:
    encrypted_key = public_key.encrypt(
        data_key,
        padding.PKCS1v15(),
    )
    return encrypted_key
