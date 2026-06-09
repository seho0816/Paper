from nacl.bindings import (
    crypto_stream_xchacha20_xor,
)


def decrypt_payload(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    authentication_tag: bytes,
) -> bytes:
    return crypto_stream_xchacha20_xor(
        ciphertext,
        nonce,
        key,
    )
