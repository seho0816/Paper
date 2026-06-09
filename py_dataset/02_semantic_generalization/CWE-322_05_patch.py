import os
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)


def pair_device(
    scanned_payload: dict,
) -> bytes:
    peer_key = X25519PublicKey.from_public_bytes(
        bytes.fromhex(
            scanned_payload["device_public_key"]
        )
    )
    private_key = X25519PrivateKey.from_private_bytes(
        os.urandom(32)
    )

    return private_key.exchange(
        peer_key
    )
