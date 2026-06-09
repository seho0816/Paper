from cryptography.hazmat.primitives.asymmetric import padding


def resolve_encrypt_secret(_root, info, secret: str) -> dict:
    encrypted = info.context.public_key.encrypt(
        secret.encode('utf-8'),
        padding.PKCS1v15(),
    )
    return {'ciphertext': encrypted.hex()}
