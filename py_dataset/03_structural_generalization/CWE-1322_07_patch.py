import requests
import json
from dataclasses import dataclass

MAX_RESPONSE_SIZE = 10 * 1024 * 1024  # 10 MB limit for decompressed response content

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
            stream=True,  # Enable streaming to read content iteratively
        )
        response.raise_for_status()

        total_size = 0
        chunks = []
        try:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    total_size += len(chunk)
                    if total_size > MAX_RESPONSE_SIZE:
                        response.close()  # Close the connection immediately
                        raise ValueError(f"Response content too large (>{MAX_RESPONSE_SIZE / (1024*1024):.1f} MB)")
                    chunks.append(chunk)

            full_content = b"".join(chunks)
            encoding = response.encoding if response.encoding else 'utf-8'
            json_string = full_content.decode(encoding)
            return json.loads(json_string)
        finally:
            response.close()
