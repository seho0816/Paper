from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def resolve_encrypt_secret(_root, info, secret: str) -> dict:
    encrypted = info.context.public_key.encrypt(
        secret.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ),
    )
    return {'ciphertext': encrypted.hex()}
