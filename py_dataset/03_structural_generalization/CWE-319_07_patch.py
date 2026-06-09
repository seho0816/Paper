import requests
from dataclasses import dataclass


@dataclass(frozen=True)
class PartnerCredentials:
    username: str
    password: str


class PartnerClient:
    def __init__(
        self,
        credentials: PartnerCredentials,
    ) -> None:
        self._credentials = credentials

    def fetch(self) -> dict:
        response = requests.post(
            "https://partner.example.com/session",  # Changed from http:// to https://
            json={
                "username": self._credentials.username,
                "password": self._credentials.password,
            },
            timeout=10,
        )

        return response.json()
