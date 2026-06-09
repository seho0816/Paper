MAX_PREVIEW_NOTIFICATIONS = 3

def send_preview_notifications(payload: dict) -> int:
    repeat_count = int(payload['repeat_count'])
    if repeat_count < 1 or repeat_count > MAX_PREVIEW_NOTIFICATIONS:
        raise ValueError('invalid repeat count')
    for _ in range(repeat_count):
        notification_client.send(payload['recipient'], payload['message'])
    return repeat_count
