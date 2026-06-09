import logging
from dataclasses import dataclass


# Placeholder for an external function, as it's not defined in the original snippet.
# In a real application, this function would be imported or defined elsewhere.
def dispatch_event(event: 'IntegrationEvent') -> None:
    pass


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
        # CWE-117: Improper Output Neutralization for Logs
        # Changed from f-string interpolation to passing arguments directly to the logger.
        # This allows the logging module to safely handle potentially malicious input
        # within event.partner_message by properly escaping or neutralizing it,
        # preventing log injection or format string vulnerabilities.
        self._logger.info(
            "event=%s type=%s message=%s",
            event.event_id,
            event.event_type,
            event.partner_message
        )

        dispatch_event(event)
