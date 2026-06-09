from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)


def exchange_with_authenticated_peer(
    peer_public_bytes: bytes,
    peer_signature: bytes,
    trusted_signing_key,
) -> bytes:
    trusted_signing_key.verify(
        peer_signature,
        peer_public_bytes,
    )
    private_key = X25519PrivateKey.generate()
    peer_public_key = X25519PublicKey.from_public_bytes(
        peer_public_bytes
    )

    return private_key.exchange(
        peer_public_key
    )
