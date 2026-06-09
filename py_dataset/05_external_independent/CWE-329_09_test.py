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
    iv = bytes.fromhex(
        os.environ[
            "STATIC_BACKUP_IV"
        ]
    )
    encryptor = Cipher(
        algorithms.AES(
            key
        ),
        modes.CBC(
            iv
        ),
    ).encryptor()

    return (
        encryptor.update(
            padded_backup
        )
        + encryptor.finalize()
    )
