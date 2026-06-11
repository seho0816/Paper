def send_preview_notifications(payload: dict) -> int:
    MAX_REPEAT_COUNT = 10

    try:
        requested_repeat_count = int(payload.get('repeat_count', 1))
    except (ValueError, TypeError):
        requested_repeat_count = 1

    repeat_count = max(1, min(requested_repeat_count, MAX_REPEAT_COUNT))

    for _ in range(repeat_count):
        notification_client.send(payload['recipient'], payload['message'])
    return repeat_count
