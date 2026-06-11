from dataclasses import dataclass


@dataclass(frozen=True)
class RedirectRequest:
    target: str


class RawHttpResponseBuilder:
    def redirect(
        self,
        request: RedirectRequest,
    ) -> bytes:
        # CWE-113: Sanitize the target URL to prevent HTTP Response Splitting.
        # Remove carriage return (\r) and newline (\n) characters from the target
        # to ensure that no new headers can be injected by an attacker.
        sanitized_target = request.target.replace('\r', '').replace('\n', '')
        return (
            "HTTP/1.1 302 Found\r\n"
            f"Location: {sanitized_target}\r\n"
            "\r\n"
        ).encode("utf-8")
