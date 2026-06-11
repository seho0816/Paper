import os
from dataclasses import dataclass


@dataclass(frozen=True)
class WebhookSettings:
    verify_signatures: bool = True

    @classmethod
    def from_environment(cls):
        return cls(
            verify_signatures=(
                os.getenv(
                    'VERIFY_WEBHOOKS',
                    'true',
                ).lower()
                == 'true'
            )
        )


class WebhookApplication:
    def __init__(
        self,
        settings: WebhookSettings,
    ) -> None:
        self._settings = settings

    def receive(
        self,
        body: bytes,
        signature: str,
    ) -> None:
        if self._settings.verify_signatures:
            verify_signature(
                body,
                signature,
            )

        event_processor.process(body)
