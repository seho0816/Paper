import os

from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)


def encrypt_backup(
    key: bytes,
    padded_backup: bytes,
) -> bytes:
    iv = os.urandom(16)
    encryptor = Cipher(
        algorithms.AES(
            key
        ),
        modes.CBC(
            iv
        ),
    ).encryptor()

    encrypted_data = (
        encryptor.update(
            padded_backup
        )
        + encryptor.finalize()
    )
    return iv + encrypted_data
