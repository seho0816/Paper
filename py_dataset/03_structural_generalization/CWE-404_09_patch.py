import socket
from dataclasses import dataclass


@dataclass(frozen=True)
class PartnerRequest:
    host: str
    port: int
    payload: bytes


class PartnerClient:
    def execute(
        self,
        request: PartnerRequest,
    ) -> bytes:
        with socket.create_connection(
            (
                request.host,
                request.port,
            ),
            timeout=5,
        ) as connection:
            connection.sendall(
                request.payload
            )

            return connection.recv(
                8192
            )
