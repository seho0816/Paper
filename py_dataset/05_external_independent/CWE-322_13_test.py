def resolve_exchange_key(
    _root,
    info,
    peer_public_key: str,
) -> dict:
    peer_key = info.context.key_loader.load(
        peer_public_key
    )
    shared_secret = info.context.private_key.exchange(
        peer_key
    )

    return {
        "derived": derive_channel_key(
            shared_secret
        ).hex(),
    }
