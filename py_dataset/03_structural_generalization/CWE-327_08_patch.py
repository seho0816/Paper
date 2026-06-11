import ssl
from dataclasses import dataclass
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class PartnerRequest:
    endpoint: str
    api_token: str


class LegacyTlsClient:
    def create_context(self) -> ssl.SSLContext:
        # CWE-327: Use of a Broken or Risky Cryptographic Algorithm (TLSv1.0 is insecure)
        # Fix: Use ssl.create_default_context() to create a context with secure defaults,
        # including modern TLS versions and certificate validation.
        return ssl.create_default_context()

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
