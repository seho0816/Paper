from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)


def derive_shared_secret(
    peer_public_bytes: bytes,
) -> bytes:
    private_key = X25519PrivateKey.generate()
    peer_public_key = X25519PublicKey.from_public_bytes(
        peer_public_bytes
    )

    return private_key.exchange(
        peer_public_key
    )
