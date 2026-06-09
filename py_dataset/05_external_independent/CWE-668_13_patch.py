subscription_registry: dict[tuple[str, str], list] = {}


def subscribe_to_private_feed(
    tenant_id: str,
    channel_id: str,
    socket,
) -> None:
    # CWE-668 Fix: Use a composite key (tenant_id, channel_id)
    # to ensure subscriptions are isolated per tenant.
    # Previously, only channel_id was used, potentially exposing one tenant's
    # subscriptions to another if channel_ids were not globally unique.
    key = (tenant_id, channel_id)
    listeners = subscription_registry.setdefault(
        key,
        [],
    )
    listeners.append(socket)
    # feed_repository is assumed to be an existing object/module.
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
    # feed_repository is assumed to be an existing object/module.
    feed_repository.save(
        tenant_id,
        channel_id,
        event,
    )

    # CWE-668 Fix: Use a composite key (tenant_id, channel_id)
    # to ensure events are published only to the correct tenant's subscribers.
    key = (tenant_id, channel_id)
    for socket in subscription_registry.get(
        key,
        [],
    ):
        socket.send_json(event)
