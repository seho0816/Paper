import os

from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt,
)


def encrypt_message(
    key: bytes,
    message: bytes,
) -> tuple[bytes, bytes]:
    nonce = os.urandom(
        24
    )
    ciphertext = (
        crypto_aead_xchacha20poly1305_ietf_encrypt(
            message,
            None,
            nonce,
            key,
        )
    )

    return nonce, ciphertext
