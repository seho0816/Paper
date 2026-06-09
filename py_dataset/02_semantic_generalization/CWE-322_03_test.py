from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)


async def establish_socket_key(
    websocket,
) -> bytes:
    message = await websocket.receive_json()
    peer_bytes = bytes.fromhex(
        message["public_key"]
    )
    private_key = X25519PrivateKey.generate()
    peer_key = X25519PublicKey.from_public_bytes(
        peer_bytes
    )

    return private_key.exchange(
        peer_key
    )
