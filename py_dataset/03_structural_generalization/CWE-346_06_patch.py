from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class WebSocketHandshake:
    origin: str | None
    host: str


class HandshakePolicy:
    def allow(
        self,
        request: WebSocketHandshake,
    ) -> bool:
        # Existing host check
        if request.host != "socket.example.com":
            return False

        # CWE-346 fix: Origin Validation
        # Reject requests that do not provide an Origin header, as it is crucial for security.
        # Legitimate browser-initiated WebSocket handshakes will always send an Origin header.
        if request.origin is None:
            return False

        try:
            # Parse the origin URL to extract its components.
            parsed_origin = urlparse(request.origin)
        except ValueError:
            # Handle cases where the origin string is malformed and cannot be parsed.
            return False

        # Extract the hostname from the parsed origin.
        # This will be None if the origin string is malformed or lacks a hostname component.
        origin_hostname = parsed_origin.hostname

        if origin_hostname is None:
            return False

        # Define the set of allowed origin hostnames.
        # These are the trusted domains from which your web application is allowed
        # to initiate WebSocket connections to this server.
        # It is critical to configure this list accurately based on your application's deployment.
        # For this example, we assume the web application is hosted on 'example.com' or 'www.example.com'.
        # 'socket.example.com' is also included if the web application itself can be served from that host.
        allowed_origin_hostnames = {
            "example.com",
            "www.example.com",
            "socket.example.com",
        }

        # Validate that the origin's hostname is within the allowed list.
        if origin_hostname not in allowed_origin_hostnames:
            return False

        # Optionally, you might also want to validate the scheme (e.g., only 'https')
        # or the port, depending on your security requirements.
        # For instance:
        # if parsed_origin.scheme not in ("https",):
        #     return False

        # If all checks (host and origin) pass, the handshake is allowed.
        return True
