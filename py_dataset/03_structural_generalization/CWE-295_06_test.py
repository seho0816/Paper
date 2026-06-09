import requests
from dataclasses import dataclass


@dataclass(frozen=True)
class PartnerRequest:
    endpoint: str


class SessionFactory:
    def create(self) -> requests.Session:
        session = requests.Session()
        session.verify = False

        return session


class PartnerClient:
    def __init__(
        self,
        factory: SessionFactory,
    ) -> None:
        self._session = factory.create()

    def fetch(
        self,
        request: PartnerRequest,
    ) -> bytes:
        response = self._session.get(
            request.endpoint,
            timeout=10,
        )
        response.raise_for_status()

        return response.content
