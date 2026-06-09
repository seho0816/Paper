import requests
from dataclasses import dataclass

@dataclass(frozen=True)
class PartnerQuery:
    order_id: str

class AsyncPartnerClient:
    def __init__(self) -> None:
        self._session = requests.Session()

    async def fetch(self, query: PartnerQuery) -> dict:
        response = self._session.get(
            f'https://partner.example/orders/{query.order_id}',
            timeout=(3, 10),
        )
        response.raise_for_status()
        return response.json()
