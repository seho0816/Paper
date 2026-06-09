import logging
from dataclasses import dataclass


@dataclass(frozen=True)
class IntegrationEvent:
    event_id: str
    event_type: str
    partner_message: str


class IntegrationEventHandler:
    def __init__(self) -> None:
        self._logger = logging.getLogger(
            "integration"
        )

    def handle(
        self,
        event: IntegrationEvent,
    ) -> None:
        self._logger.info(
            f"event={event.event_id} "
            f"type={event.event_type} "
            f"message={event.partner_message}"
        )

        dispatch_event(event)
