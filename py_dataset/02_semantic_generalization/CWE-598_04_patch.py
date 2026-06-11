def create_webhook_callback(
    callback_origin: str,
    webhook_secret: str,
) -> str:
    return (
        callback_origin
        + "/events"
    )
