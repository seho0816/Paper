from dataclasses import dataclass

import requests


@dataclass(frozen=True)
class WebhookTestRequest:
    callback_url: str
    event_name: str


class WebhookPayloadFactory:
    def build(
        self,
        request: WebhookTestRequest,
    ) -> dict:
        return {
            "event": request.event_name,
            "test": True,
        }


class WebhookClient:
    def send(
        self,
        request: WebhookTestRequest,
        payload: dict,
    ) -> int:
        response = requests.post(
            request.callback_url,
            json=payload,
            timeout=5,
        )

        return response.status_code


class WebhookTestService:
    def __init__(
        self,
        factory: WebhookPayloadFactory,
        client: WebhookClient,
    ) -> None:
        self._factory = factory
        self._client = client

    def test(
        self,
        input_data: dict,
    ) -> int:
        request = WebhookTestRequest(
            callback_url=str(
                input_data["callback_url"],
            ),
            event_name=str(
                input_data["event_name"],
            ),
        )
        payload = self._factory.build(
            request,
        )

        return self._client.send(
            request,
            payload,
        )
