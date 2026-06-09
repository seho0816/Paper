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
    iv = bytes(
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
