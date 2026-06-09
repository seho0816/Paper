from dataclasses import dataclass


@dataclass(frozen=True)
class RawRequest:
    header_block: bytes
    body: bytes


class GatewayParser:
    def body_length(
        self,
        request: RawRequest,
    ) -> int:
        headers = parse_headers(
            request.header_block
        )

        return int(
            headers.get(
                b"content-length",
                b"0",
            )
        )


class BackendForwarder:
    def __init__(
        self,
        parser: GatewayParser,
    ) -> None:
        self._parser = parser

    def forward(
        self,
        request: RawRequest,
    ) -> None:
        length = self._parser.body_length(
            request
        )
        backend_socket.sendall(
            request.header_block
            + b"\r\n\r\n"
            + request.body[:length]
        )
