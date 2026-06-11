def receive_webhook(body: bytes, signature: str) -> None:
    verification_code = webhook_signer.verify(body, signature)
    if verification_code != 0:  # CWE-253: Ensure all non-zero return values are handled as errors.
        raise PermissionError('webhook rejected')
    webhook_events.publish(body)
