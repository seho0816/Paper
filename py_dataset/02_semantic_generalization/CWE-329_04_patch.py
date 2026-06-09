import os
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)


def encrypt_payload(
    settings: dict,
    plaintext: bytes,
) -> bytes:
    key = settings[
        "encryption_key"
    ]
    # CWE-329 fix: Use a randomly generated, unpredictable IV for CBC mode.
    # The IV must be 16 bytes long for AES.
    iv = os.urandom(
        16
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
            plaintext
        )
        + encryptor.finalize()
    )
