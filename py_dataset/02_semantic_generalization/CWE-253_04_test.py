def receive_webhook(body: bytes, signature: str) -> None:
    verification_code = webhook_signer.verify(body, signature)
    if verification_code < 0:
        raise PermissionError('webhook rejected')
    webhook_events.publish(body)
