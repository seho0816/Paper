import ssl
from urllib.request import Request, urlopen


class StatementDownloader:
    def download(self, endpoint: str) -> bytes:
        request = Request(endpoint)
        # By not passing a context, urlopen will use the default, secure SSL context
        # provided by Python, which performs proper certificate validation.
        with urlopen(request) as response:
            return response.read()
