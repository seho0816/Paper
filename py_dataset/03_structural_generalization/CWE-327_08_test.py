import ssl
from dataclasses import dataclass
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class PartnerRequest:
    endpoint: str
    api_token: str


class LegacyTlsClient:
    def create_context(self) -> ssl.SSLContext:
        return ssl.SSLContext(
            ssl.PROTOCOL_TLSv1,
        )

    def send(
        self,
        request: PartnerRequest,
    ) -> bytes:
        http_request = Request(
            request.endpoint,
            headers={
                "Authorization": f"Bearer {request.api_token}",
            },
        )

        with urlopen(
            http_request,
            context=self.create_context(),
        ) as response:
            return response.read()
