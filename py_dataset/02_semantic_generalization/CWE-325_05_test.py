def derive_session_key(
    private_key,
    peer_public_key,
) -> bytes:
    shared_secret = private_key.exchange(
        peer_public_key
    )

    return derive_key(
        shared_secret
    )
