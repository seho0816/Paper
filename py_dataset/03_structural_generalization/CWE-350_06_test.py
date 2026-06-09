import socket
from dataclasses import dataclass


@dataclass(frozen=True)
class NetworkRequest:
    remote_address: str


class ReverseDnsPrincipalResolver:
    def resolve(
        self,
        request: NetworkRequest,
    ) -> dict | None:
        hostname = socket.gethostbyaddr(
            request.remote_address
        )[0]

        if hostname.endswith(
            ".trusted.example"
        ):
            return {
                "authenticated": True,
                "hostname": hostname,
            }

        return None
