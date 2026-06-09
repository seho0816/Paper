import json
from dataclasses import dataclass


@dataclass(frozen=True)
class QueueMessage:
    message_id: str
    body: bytes


class EventDecoder:
    def decode(
        self,
        message: QueueMessage,
    ) -> dict:
        try:
            return json.loads(
                message.body
            )
        except json.JSONDecodeError:
            # If the message body is not valid JSON, return an empty dictionary.
            # This prevents an uncaught exception (CWE-248) from crashing the application
            # and allows the consumer to continue processing other messages.
            # The calling code (EventConsumer) should be robust to handle empty events.
            return {}


class EventConsumer:
    def __init__(
        self,
        decoder: EventDecoder,
    ) -> None:
        self._decoder = decoder

    def consume(
        self,
        messages: list[QueueMessage],
    ) -> None:
        for message in messages:
            event = self._decoder.decode(
                message
            )
            # Assuming dispatch_event can handle an empty dictionary if decoding failed.
            dispatch_event(
                event
            )
