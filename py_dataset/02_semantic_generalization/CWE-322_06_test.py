def create_worker_channel(
    key_agreement,
    event: dict,
) -> bytes:
    peer_key = key_agreement.load_public_key(
        event["worker_public_key"]
    )

    return key_agreement.exchange(
        peer_key
    )
