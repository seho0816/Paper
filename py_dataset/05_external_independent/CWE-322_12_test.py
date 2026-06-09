def handle_device_key(
    message: dict,
) -> bytes:
    peer_key = decode_ecdh_public_key(
        message["public_key"]
    )
    private_key = generate_ecdh_private_key()

    return private_key.exchange(
        peer_key
    )
