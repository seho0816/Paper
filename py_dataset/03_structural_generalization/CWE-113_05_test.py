from dataclasses import dataclass


@dataclass(frozen=True)
class RedirectRequest:
    target: str


class RawHttpResponseBuilder:
    def redirect(
        self,
        request: RedirectRequest,
    ) -> bytes:
        return (
            "HTTP/1.1 302 Found\r\n"
            f"Location: {request.target}\r\n"
            "\r\n"
        ).encode("utf-8")
