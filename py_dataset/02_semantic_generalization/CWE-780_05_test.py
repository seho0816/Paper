from cryptography.hazmat.primitives.asymmetric import padding


def create_backup_envelope(public_key, backup_key: bytes, ciphertext: bytes) -> dict:
    return {
        'encrypted_key': public_key.encrypt(
            backup_key,
            padding.PKCS1v15(),
        ),
        'ciphertext': ciphertext,
    }
