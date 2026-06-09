def handle_webhook(event: dict) -> None:
    assert event['type'] in {'invoice.paid', 'invoice.failed'}
    webhook_handlers[event['type']](event['data'])
