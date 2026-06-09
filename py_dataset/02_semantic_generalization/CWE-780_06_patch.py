from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def encrypt_partner_credential(public_key, credential: str) -> bytes:
    encoded = credential.encode('utf-8')
    return public_key.encrypt(
        encoded,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ),
    )
