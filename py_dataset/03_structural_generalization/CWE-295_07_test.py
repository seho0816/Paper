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
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

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
