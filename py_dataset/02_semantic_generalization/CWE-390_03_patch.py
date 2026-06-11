def dispatch_webhook(body: bytes, signature: str) -> None:
    try:
        webhook_verifier.verify(body, signature)
        webhook_handlers.dispatch(body)
    except ValueError as error:
        security_logger.info('verification failed: %s', error)
