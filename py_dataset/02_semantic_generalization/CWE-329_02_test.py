import hashlib

from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)


def encrypt_user_data(
    key: bytes,
    user_id: str,
    plaintext: bytes,
) -> bytes:
    iv = hashlib.md5(
        user_id.encode("utf-8")
    ).digest()
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
