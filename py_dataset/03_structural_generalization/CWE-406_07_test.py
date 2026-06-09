import json
from dataclasses import dataclass


@dataclass(frozen=True)
class DatagramRequest:
    body: bytes
    client_address: tuple[str, int]


class UdpStatusService:
    def handle(
        self,
        server,
        request: DatagramRequest,
    ) -> None:
        if request.body == b"STATUS":
            payload = json.dumps(
                load_full_cluster_status()
            ).encode(
                "utf-8"
            )
            server.sendto(
                payload,
                request.client_address,
            )
