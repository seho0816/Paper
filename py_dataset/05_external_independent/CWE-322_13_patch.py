def resolve_exchange_key(
    _root,
    info,
    peer_public_key: str,
) -> dict:
    if not hasattr(info.context, 'authenticated_peer_public_key') or \
       info.context.authenticated_peer_public_key is None:
        raise PermissionError("Peer authentication information is missing in context.")
    
    if peer_public_key != info.context.authenticated_peer_public_key:
        raise PermissionError("Provided public key does not match authenticated peer's public key.")

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
