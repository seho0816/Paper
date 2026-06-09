from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)


def decrypt_record(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
) -> bytes:
    decryptor = Cipher(
        algorithms.AES(
            key
        ),
        modes.CTR(
            nonce
        ),
    ).decryptor()

    return (
        decryptor.update(
            ciphertext
        )
        + decryptor.finalize()
    )
