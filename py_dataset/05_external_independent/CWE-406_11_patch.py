import asyncio
import json
import time


class StatusProtocol(
    asyncio.DatagramProtocol
):
    _last_request_time = {}
    _cooldown_period = 5

    def datagram_received(
        self,
        data: bytes,
        address,
    ) -> None:
        if data != b"STATUS":
            return

        current_time = time.monotonic()
        last_time = self._last_request_time.get(address)

        if last_time is not None and (current_time - last_time) < self._cooldown_period:
            return

        self._last_request_time[address] = current_time

        payload = json.dumps(
            load_full_cluster_status()
        ).encode(
            "utf-8"
        )
        self.transport.sendto(
            payload,
            address,
        )
