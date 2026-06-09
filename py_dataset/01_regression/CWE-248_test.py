import json


def run_event_worker(
    messages: list[bytes],
) -> None:
    for raw_message in messages:
        event = json.loads(
            raw_message
        )
        dispatch_event(
            event
        )
