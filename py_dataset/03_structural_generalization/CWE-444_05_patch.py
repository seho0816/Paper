from dataclasses import dataclass


@dataclass(frozen=True)
class RawRequest:
    header_block: bytes
    body: bytes


# parse_headers and backend_socket are assumed to be defined elsewhere as per the original code's context.
# Example (not part of the solution, just for context understanding):
# def parse_headers(header_block: bytes) -> dict[bytes, bytes]:
#     # ... implementation ...
#     pass
#
# backend_socket = ... # A socket object


class GatewayParser:
    def body_length(
        self,
        request: RawRequest,
    ) -> int:
        headers = parse_headers(
            request.header_block
        )

        # CWE-444 Fix: Ensure Content-Length is consistently and safely interpreted.
        # Malformed or negative Content-Length values can lead to inconsistent interpretation
        # between components (e.g., this gateway and a backend server), potentially causing
        # request smuggling, data truncation, or unexpected behavior.
        # This modification ensures that:
        # 1. Non-integer Content-Length values are treated as 0 (preventing ValueError crash).
        # 2. Negative Content-Length values are treated as 0 (standard HTTP content lengths must be non-negative).
        try:
            length_str = headers.get(
                b"content-length",
                b"0",
            ).decode('ascii') # Decode to string for int()
            length = int(length_str)
        except (ValueError, UnicodeDecodeError):
            # If decoding fails or conversion to int fails, treat length as 0.
            # This provides a consistent interpretation for malformed headers.
            length = 0

        return max(0, length)


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
