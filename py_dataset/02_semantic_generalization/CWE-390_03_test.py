def dispatch_webhook(body: bytes, signature: str) -> None:
    try:
        webhook_verifier.verify(body, signature)
    except ValueError as error:
        security_logger.info('verification failed: %s', error)
    webhook_handlers.dispatch(body)
