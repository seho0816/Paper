from cryptography.hazmat.primitives.asymmetric import padding


def encrypt_device_secret(device_public_key, secret: bytes) -> bytes:
    return device_public_key.encrypt(
        secret,
        padding.PKCS1v15(),
    )
