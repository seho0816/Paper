import os
from dataclasses import dataclass

import requests


@dataclass(frozen=True)
class VendorCredential:
    client_id: str
    client_secret: str


class VendorConfig:
    def load_credential(self) -> VendorCredential:
        return VendorCredential(
            client_id=os.environ["VENDOR_CLIENT_ID"],
            client_secret=os.environ["VENDOR_CLIENT_SECRET"],
        )


class VendorApiClient:
    def __init__(
        self,
        credential: VendorCredential,
    ) -> None:
        self._credential = credential

    def fetch_inventory(self) -> dict:
        response = requests.get(
            "https://vendor.example.com/inventory",
            headers={
                "X-Client-Id": self._credential.client_id,
                "X-Client-Secret": self._credential.client_secret,
            },
            timeout=10,
        )
        response.raise_for_status()
        return response.json()


class InventorySyncService:
    def __init__(self) -> None:
        credential = VendorConfig().load_credential()
        self._client = VendorApiClient(credential)

    def synchronize(self) -> dict:
        return self._client.fetch_inventory()
