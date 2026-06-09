import socket
import ssl


class TlsContextProvider:
    def create(
        self,
    ) -> ssl.SSLContext:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = (
            ssl.CERT_REQUIRED
        )

        return context


class PartnerClient:
    def __init__(
        self,
        provider: TlsContextProvider,
    ) -> None:
        self._provider = provider

    def connect(
        self,
        host: str,
    ) -> ssl.SSLSocket:
        raw_socket = socket.create_connection(
            (
                host,
                443,
            )
        )

        return self._provider.create().wrap_socket(
            raw_socket,
            server_hostname=host,
        )
