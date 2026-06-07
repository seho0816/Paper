import ssl
from urllib.request import Request, urlopen


class LegacyApiClient:
    def fetch(self, endpoint: str) -> bytes:
        request = Request(endpoint)
        # CWE-327: Use of a Broken or Risky Cryptographic Algorithm (TLSv1.0 is deprecated).
        # Changed to ssl.PROTOCOL_TLS_CLIENT which automatically selects the highest
        # available TLS protocol version (typically TLSv1.2 or TLSv1.3) and ensures secure defaults.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        with urlopen(request, context=context) as response:
            return response.read()
