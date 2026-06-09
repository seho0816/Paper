import ssl
from urllib.request import Request, urlopen


class LegacyApiClient:
    def fetch(self, endpoint: str) -> bytes:
        request = Request(endpoint)
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)

        with urlopen(request, context=context) as response:
            return response.read()
