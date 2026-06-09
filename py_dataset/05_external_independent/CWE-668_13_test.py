subscription_registry: dict[str, list] = {}


def subscribe_to_private_feed(
    tenant_id: str,
    channel_id: str,
    socket,
) -> None:
    listeners = subscription_registry.setdefault(
        channel_id,
        [],
    )
    listeners.append(socket)
    socket.send_json(
        feed_repository.load_latest(
            tenant_id,
            channel_id,
        )
    )


def publish_private_feed(
    tenant_id: str,
    channel_id: str,
    event: dict,
) -> None:
    feed_repository.save(
        tenant_id,
        channel_id,
        event,
    )

    for socket in subscription_registry.get(
        channel_id,
        [],
    ):
        socket.send_json(event)
