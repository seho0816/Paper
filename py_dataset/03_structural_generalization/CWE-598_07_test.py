import requests
from dataclasses import dataclass


@dataclass(frozen=True)
class ProfileRequest:
    endpoint: str
    access_token: str


class ProfileApiClient:
    def fetch(
        self,
        request: ProfileRequest,
    ) -> dict:
        url = (
            request.endpoint
            + "?access_token="
            + request.access_token
        )
        response = requests.get(
            url,
            timeout=5,
        )

        return response.json()
