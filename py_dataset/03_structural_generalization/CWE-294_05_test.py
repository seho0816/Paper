import json
from dataclasses import dataclass


@dataclass(frozen=True)
class SignedWebhook:
    raw_body: bytes
    signature: str


class WebhookVerifier:
    def verify(
        self,
        webhook: SignedWebhook,
    ) -> bool:
        return verify_signature(
            webhook.raw_body,
            webhook.signature,
        )


class WebhookService:
    def __init__(
        self,
        verifier: WebhookVerifier,
    ) -> None:
        self._verifier = verifier

    def handle(
        self,
        webhook: SignedWebhook,
    ) -> None:
        if not self._verifier.verify(
            webhook
        ):
            raise PermissionError(
                "invalid signature"
            )

        event = json.loads(
            webhook.raw_body
        )
        process_event(event)
