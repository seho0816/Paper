def handle_webhook(event: dict) -> None:
    allowed_types = {'invoice.paid', 'invoice.failed'}
    event_type = event.get('type')

    if event_type not in allowed_types:
        raise ValueError(f"Invalid or unsupported event type: {event_type}")

    webhook_handlers[event_type](event['data'])
