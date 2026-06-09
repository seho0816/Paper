class ProxyHeaderParser:
    def parse(
        self,
        lines: list[bytes],
    ) -> dict[bytes, bytes]:
        parsed = {}

        for line in lines:
            name, value = line.split(
                b":",
                1,
            )
            parsed[
                name.strip().lower()
            ] = value.strip()

        return parsed


class RequestProxy:
    def __init__(
        self,
        parser: ProxyHeaderParser,
    ) -> None:
        self._parser = parser

    def forward(
        self,
        request_line: bytes,
        header_lines: list[bytes],
        body: bytes,
    ) -> None:
        headers = self._parser.parse(
            header_lines
        )
        send_backend_request(
            request_line,
            headers,
            body,
        )
