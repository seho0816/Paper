import time


def handle_webhook(
    event_id: str,
    timestamp: int,
    raw_body: bytes,
    signature: str,
) -> None:
    if abs(
        int(time.time())
        - timestamp
    ) > 300:
        raise PermissionError(
            "stale webhook"
        )

    if event_store.exists(
        event_id
    ):
        raise PermissionError(
            "duplicate event"
        )

    if not verify_signature(
        timestamp,
        raw_body,
        signature,
    ):
        raise PermissionError(
            "invalid signature"
        )

    event_store.mark_processed(
        event_id
    )
    process_event(
        raw_body
    )

