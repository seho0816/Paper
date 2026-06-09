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
        return json.loads(
            message.body
        )


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
            dispatch_event(
                event
            )
