import json
from dataclasses import dataclass


@dataclass(frozen=True)
class WebhookRequest:
    raw_body: bytes
    signature: str


class WebhookDecoder:
    def decode(
        self,
        request: WebhookRequest,
    ) -> dict:
        return json.loads(
            request.raw_body,
        )


class OrderWebhookService:
    def __init__(
        self,
        decoder: WebhookDecoder,
    ) -> None:
        self._decoder = decoder

    def handle(
        self,
        request: WebhookRequest,
    ) -> None:
        event = self._decoder.decode(
            request,
        )

        if event["type"] == "order.refunded":
            mark_order_refunded(
                event["order_id"],
            )
