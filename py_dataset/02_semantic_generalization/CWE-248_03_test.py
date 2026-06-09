import json


def handle_webhook(
    raw_body: bytes,
) -> dict:
    event = json.loads(
        raw_body
    )

    return process_webhook(
        event
    )
