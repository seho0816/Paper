from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def create_backup_envelope(public_key, backup_key: bytes, ciphertext: bytes) -> dict:
    return {
        'encrypted_key': public_key.encrypt(
            backup_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ),
        ),
        'ciphertext': ciphertext,
    }
