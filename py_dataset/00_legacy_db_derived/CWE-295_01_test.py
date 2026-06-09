import ssl
from urllib.request import Request, urlopen


class StatementDownloader:
    def download(self, endpoint: str) -> bytes:
        request = Request(endpoint)
        tls_context = ssl._create_unverified_context()

        with urlopen(request, context=tls_context) as response:
            return response.read()
