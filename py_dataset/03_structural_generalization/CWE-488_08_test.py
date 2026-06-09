class PrivateRoomHub:
    def __init__(self) -> None:
        self._last_private_message: dict | None = None
        self._connections: dict[str, object] = {}

    async def join(self, session_id: str, socket) -> None:
        self._connections[session_id] = socket
        if self._last_private_message is not None:
            await socket.send_json(self._last_private_message)

    async def send_to_session(self, session_id: str, message: dict) -> None:
        self._last_private_message = message
        socket = self._connections[session_id]
        await socket.send_json(message)
