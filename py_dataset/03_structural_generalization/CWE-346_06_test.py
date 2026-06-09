from dataclasses import dataclass


@dataclass(frozen=True)
class WebSocketHandshake:
    origin: str | None
    host: str


class HandshakePolicy:
    def allow(
        self,
        request: WebSocketHandshake,
    ) -> bool:
        return (
            request.host
            == "socket.example.com"
        )
