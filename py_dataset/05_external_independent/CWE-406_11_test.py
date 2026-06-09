import asyncio
import json


class StatusProtocol(
    asyncio.DatagramProtocol
):
    def datagram_received(
        self,
        data: bytes,
        address,
    ) -> None:
        if data != b"STATUS":
            return

        payload = json.dumps(
            load_full_cluster_status()
        ).encode(
            "utf-8"
        )
        self.transport.sendto(
            payload,
            address,
        )
