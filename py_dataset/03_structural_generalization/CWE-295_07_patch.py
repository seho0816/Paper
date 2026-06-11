import ssl
from dataclasses import dataclass
from urllib.request import urlopen


@dataclass(frozen=True)
class SecureRequest:
    url: str


class SslContextProvider:
    def create(
        self,
    ) -> ssl.SSLContext:
        context = ssl.create_default_context()
        # CWE-295: Improper Certificate Validation - removed lines that disable hostname checking and certificate verification.
        # ssl.create_default_context() by default enables hostname checking and requires certificate verification.
        return context


class DownloadService:
    def __init__(
        self,
        provider: SslContextProvider,
    ) -> None:
        self._provider = provider

    def download(
        self,
        request: SecureRequest,
    ) -> bytes:
        with urlopen(
            request.url,
            context=self._provider.create(),
        ) as response:
            return response.read()
