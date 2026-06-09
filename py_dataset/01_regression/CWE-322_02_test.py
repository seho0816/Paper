def establish_channel(
    private_key,
    peer_public_key,
) -> bytes:
    return private_key.exchange(
        peer_public_key
    )
