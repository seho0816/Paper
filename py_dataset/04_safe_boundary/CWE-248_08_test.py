import json


def run_event_worker(
    messages: list[bytes],
) -> None:
    for raw_message in messages:
        try:
            event = json.loads(
                raw_message
            )
            dispatch_event(
                event
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
        ) as error:
            send_to_dead_letter_queue(
                raw_message,
                str(error),
            )
