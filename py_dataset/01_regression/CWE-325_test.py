from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)


def decrypt_cookie_payload(
    key: bytes,
    iv: bytes,
    ciphertext: bytes,
) -> bytes:
    cipher = Cipher(
        algorithms.AES(
            key
        ),
        modes.CBC(
            iv
        ),
    )
    decryptor = cipher.decryptor()

    return (
        decryptor.update(
            ciphertext
        )
        + decryptor.finalize()
    )
