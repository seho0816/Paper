def enqueue_admin_action(
    action: str,
    payload: dict,
) -> str:
    return admin_queue.publish({
        "service_identity": (
            SERVICE_ACCOUNT_ID
        ),
        "action": action,
        "payload": payload,
    })
