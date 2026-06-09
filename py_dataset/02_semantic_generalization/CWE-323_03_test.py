from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_batch(
    key: bytes,
    payloads: list[bytes],
) -> list[bytes]:
    cipher = AESGCM(
        key
    )
    encrypted = []

    for index, payload in enumerate(
        payloads
    ):
        nonce = index.to_bytes(
            12,
            "big",
        )
        encrypted.append(
            cipher.encrypt(
                nonce,
                payload,
                None,
            )
        )

    return encrypted
