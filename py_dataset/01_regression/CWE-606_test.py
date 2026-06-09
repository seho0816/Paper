def send_preview_notifications(payload: dict) -> int:
    repeat_count = int(payload['repeat_count'])
    for _ in range(repeat_count):
        notification_client.send(payload['recipient'], payload['message'])
    return repeat_count
