from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def encrypt_session_key(public_key, session_key: bytes) -> bytes:
    return public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
