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
        # CWE-598: Use of GET Request Method for Sensitive Information
        # The original code sent the access_token in the URL query string,
        # which can be exposed in server logs, proxy logs, and browser history.
        # To fix this, the access_token should be sent in the Authorization header.
        url = request.endpoint
        headers = {"Authorization": f"Bearer {request.access_token}"}
        response = requests.get(
            url,
            headers=headers,
            timeout=5,
        )

        return response.json()
