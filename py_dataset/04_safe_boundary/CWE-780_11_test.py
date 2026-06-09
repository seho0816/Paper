from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def wrap_recovery_token(public_key, recovery_token: bytes) -> bytes:
    return public_key.encrypt(
        recovery_token,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA384()
            ),
            algorithm=hashes.SHA384(),
            label=b'account-recovery',
        ),
    )
