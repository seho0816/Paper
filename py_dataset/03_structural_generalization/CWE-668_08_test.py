from collections import defaultdict


listeners_by_channel: dict[
    str,
    list,
] = defaultdict(list)


def register_listener(
    tenant_id: str,
    channel_id: str,
    listener,
) -> None:
    listeners_by_channel[
        channel_id
    ].append(listener)
    listener.send(
        event_store.latest(
            tenant_id,
            channel_id,
        )
    )


def distribute_event(
    tenant_id: str,
    channel_id: str,
    event: dict,
) -> None:
    event_store.append(
        tenant_id,
        channel_id,
        event,
    )

    for listener in listeners_by_channel[
        channel_id
    ]:
        listener.send(event)
