import os
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.exceptions import InvalidKey


async def establish_socket_key(
    websocket,
) -> bytes:
    message = await websocket.receive_json()
    peer_bytes = bytes.fromhex(
        message["public_key"]
    )

    # CWE-322: Key Exchange without Entity Authentication
    # To mitigate this, the peer's public key must be authenticated.
    # We introduce a mechanism to verify the received peer's public key
    # against a pre-configured trusted public key, obtained from an environment variable.
    # This ensures that the key exchange is only performed with an authenticated entity.
    trusted_peer_public_key_hex = os.environ.get("TRUSTED_PEER_PUBLIC_KEY")
    if not trusted_peer_public_key_hex:
        # If no trusted public key is configured, authentication cannot be performed.
        # This function must enforce authentication to fix CWE-322.
        raise ValueError("TRUSTED_PEER_PUBLIC_KEY environment variable is not set. Entity authentication is required.")

    try:
        trusted_peer_public_bytes = bytes.fromhex(trusted_peer_public_key_hex)
        trusted_peer_key = X25519PublicKey.from_public_bytes(trusted_peer_public_bytes)
    except Exception as e:
        # Catch potential errors if the environment variable contains an invalid key format.
        raise ValueError(f"Invalid TRUSTED_PEER_PUBLIC_KEY configured: {e}") from e

    private_key = X25519PrivateKey.generate()
    peer_key = X25519PublicKey.from_public_bytes(
        peer_bytes
    )

    # Perform entity authentication by comparing the received key with the trusted key.
    if peer_key != trusted_peer_key:
        raise InvalidKey("Received public key does not match the trusted peer public key.")

    return private_key.exchange(
        peer_key
    )
